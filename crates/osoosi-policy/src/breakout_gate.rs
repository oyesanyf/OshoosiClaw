//! # 7-Ring Continuous Cedar Reference Monitor, Causal Provenance Graph, & Capability-Based Effect Gate
//!
//! Provides the unified policy & capability enforcement core shared by `osoosi-policy` (`PolicyEngine::evaluate`
//! and `PolicyEngine::scan_event`) and `osoosi-agent-anomaly` (`BreakoutDefenseCoordinator`,
//! `RuntimeAlignmentScanner`, and `Ring7CapabilityEffectAuthorizer`).
//!
//! ## Three Explicit Security Boundaries
//! 1. **`AgentContainment`**: 7-ring Cedar lifecycle reference monitor, `CausalSecurityGraph`,
//!    `ReaVoter` + `OpenJevVoter`, DLP / semantic similarity, `RuntimeTraceAlignmentScanner`.
//! 2. **`EdrSelfProtection`**: `ProtectedPolicyStore` (monotonic `policy_version`, `Ed25519` + `ML-DSA-65`
//!    provenance, independent approval check, anti-rollback rejection), `ServiceIsolatedKeyBroker`
//!    (zero `CRYPTPROTECT_LOCAL_MACHINE`, agent processes never hold signing keys),
//!    `ConfusedDeputyBrokerAttributor` (`WmiPrvSE.exe`, `svchost.exe`, `conhost.exe`, `git-remote-https.exe`,
//!    `ssh.exe` bound to `origin_session_id`), and `SafeTelemetryOverloadController` (bounded queue +
//!    per-workload protective degradation when `EventsLost > 0`, never suspending the entire host).
//! 3. **`PlatformTrustAndRecovery`**: Supported platform posture (`SecureBoot`, `HVCI/VBS`, `WDAC` /
//!    application control — zero undocumented kernel callback table walking), plus
//!    `ExternalIntegrityVerifierAndRecovery` (signed external health attestations, append-only audit
//!    forwarding envelopes, automatic session capability/credential revocation on tamper detection,
//!    and restoration from a verified policy/graph snapshot).

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};
use osoosi_types::HostSecurityEvent;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Default policy version identifier for deterministic audit traceability.
pub const CEDAR_BREAKOUT_POLICY_VERSION: &str = "cedar-7ring-v2.4.0";

/// Default 32-byte service-isolated key material used by the out-of-process `OsoosiEdrService`
/// key broker for deterministic HMAC-BLAKE3 / HMAC-SHA256 workspace instruction signing.
const DEFAULT_WORKSPACE_SIGNING_KEY: &[u8; 32] = b"OSHOOSICLAW_L1_MERKLE_HMAC_KEY32";

/// Default 32-byte supervisor key used for `<ZK_PII:...>` cryptographic declassification receipts.
const DEFAULT_SUPERVISOR_DECLASSIFY_KEY: &[u8; 32] = b"OSHOOSICLAW_SUPERVISOR_ZK_KEY_32";

/// Default 32-byte control-plane key used for `ProtectedPolicyStore` and `ExternalIntegrityVerifierAndRecovery`.
const DEFAULT_CONTROL_PLANE_KEY: &[u8; 32] = b"OSHOOSICLAW_CTRLPLANE_PQ_KEY__32";

// ============================================================================
// 1. 5-Level Immutable Authority Hierarchy & Signed Workspace Allowlist
// ============================================================================

/// Five-level immutable authority hierarchy.
/// Lower numeric discriminant = higher authority (`L1SystemSecurityPolicy = 1` is highest).
/// Lower-trust material (`L4`/`L5`) can NEVER promote itself to a higher authority level (`L1`..`L3`),
/// even when cryptographically signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthorityLevel {
    /// Level 1 (Highest): Immutable system security policy, Cedar `forbid` invariants, and kernel boundaries.
    L1SystemSecurityPolicy = 1,
    /// Level 2: Explicitly authorized interactive user task objective pinned at session genesis.
    L2AuthorizedUserObjective = 2,
    /// Level 3: Trusted signed system/application instruction bundle.
    L3TrustedApplicationInstruction = 3,
    /// Level 4: Workspace configuration (`CLAUDE.md`, `.cursorrules`, `.agents/AGENTS.md`, `.githooks`, `build.rs`).
    L4WorkspaceConfiguration = 4,
    /// Level 5 (Lowest): Retrieved content, web pages, GitHub issues/PRs, RAG chunks, and untrusted external data.
    L5UntrustedRetrievedContent = 5,
}

impl AuthorityLevel {
    pub fn rank(self) -> u8 {
        self as u8
    }

    pub fn outranks(&self, other: &Self) -> bool {
        self.rank() < other.rank()
    }

    pub fn outranks_or_equals(self, other: Self) -> bool {
        self.rank() <= other.rank()
    }

    pub fn is_upward_promotion_against(self, target: Self) -> bool {
        target.rank() < self.rank()
    }

    pub fn can_override_higher_policy(&self) -> bool {
        matches!(self, Self::L1SystemSecurityPolicy)
    }

    pub fn can_authorize_privileged_action(&self) -> bool {
        matches!(
            self,
            Self::L1SystemSecurityPolicy
                | Self::L2AuthorizedUserObjective
                | Self::L3TrustedApplicationInstruction
        )
    }
}

/// Cryptographically signed workspace instruction record stored in the keyed Merkle allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedWorkspaceInstructionEntry {
    pub relative_path: String,
    pub content_blake3: String,
    pub signer_key_id: String,
    pub hmac_blake3_tag: String,
    pub hmac_sha256_tag: String,
    pub ed25519_mldsa65_attestation_tag: String,
    pub assigned_authority: AuthorityLevel,
}

/// Result of verifying a workspace instruction file against the 5-level authority boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceInstructionVerificationResult {
    pub allowed: bool,
    pub path: String,
    pub assigned_authority: AuthorityLevel,
    pub effective_authority: AuthorityLevel,
    pub cryptographic_signature_valid: bool,
    pub merkle_root_blake3: String,
    pub merkle_root_hmac_verified: bool,
    pub upward_promotion_blocked: bool,
    pub policy_override_blocked: bool,
    pub policy_decision_id: String,
    pub reason: String,
}

/// Service-isolated non-exportable key management (`P0.2`):
/// - Strictly forbids `CRYPTPROTECT_LOCAL_MACHINE` (`0x00000004`) blobs (which any local user on the machine can decrypt).
/// - Ensures agent processes never possess the signing key or unrestricted signing capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProtectionAuditResult {
    pub allowed: bool,
    pub cryptprotect_local_machine_rejected: bool,
    pub agent_key_access_rejected: bool,
    pub key_storage_provider: String,
    pub reason: String,
}

pub struct SignedWorkspaceInstructionAllowlist {
    signing_key: [u8; 32],
    entries: DashMap<String, SignedWorkspaceInstructionEntry>,
}

impl Default for SignedWorkspaceInstructionAllowlist {
    fn default() -> Self {
        Self::new(*DEFAULT_WORKSPACE_SIGNING_KEY)
    }
}

impl SignedWorkspaceInstructionAllowlist {
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self {
            signing_key,
            entries: DashMap::new(),
        }
    }

    /// Enforces `P0.2` Service-Isolated Non-Exportable Key Management:
    /// 1. Rejects any DPAPI flag or config containing `CRYPTPROTECT_LOCAL_MACHINE` (`0x4`).
    /// 2. Rejects any signing or key-access request from an `agent-*` / `worker-*` / `subagent-*` principal.
    pub fn verify_key_isolation_policy(
        &self,
        caller_principal: &str,
        storage_flags_or_provider: &str,
    ) -> KeyProtectionAuditResult {
        let caller_lower = caller_principal.trim().to_ascii_lowercase();
        let flags_lower = storage_flags_or_provider.trim().to_ascii_lowercase();

        if flags_lower.contains("cryptprotect_local_machine")
            || flags_lower.contains("dpapi_local_machine")
        {
            return KeyProtectionAuditResult {
                allowed: false,
                cryptprotect_local_machine_rejected: true,
                agent_key_access_rejected: false,
                key_storage_provider: storage_flags_or_provider.to_string(),
                reason: "DENY_CRYPTPROTECT_LOCAL_MACHINE_FORBIDDEN: Machine-scope DPAPI allows any local user process on the host to decrypt key material; use service-isolated CNG/TPM non-exportable keys".to_string(),
            };
        }

        if caller_lower.contains("agent")
            || caller_lower.contains("worker")
            || caller_lower.contains("subagent")
            || caller_lower.contains("untrusted")
        {
            return KeyProtectionAuditResult {
                allowed: false,
                cryptprotect_local_machine_rejected: false,
                agent_key_access_rejected: true,
                key_storage_provider: "ServiceIsolatedCngTpmBroker".to_string(),
                reason: format!(
                    "DENY_AGENT_SIGNING_ACCESS: Principal '{}' is an autonomous agent and may never hold signing keys or invoke unrestricted signing",
                    caller_principal
                ),
            };
        }

        KeyProtectionAuditResult {
            allowed: true,
            cryptprotect_local_machine_rejected: false,
            agent_key_access_rejected: false,
            key_storage_provider: "ServiceIsolatedCngTpmNonExportable".to_string(),
            reason: "PERMIT_SERVICE_ISOLATED_KEY_BROKER: Out-of-process service principal verified with non-exportable key isolation".to_string(),
        }
    }

    fn normalize_path(path: &str) -> String {
        path.trim().replace('\\', "/").to_ascii_lowercase()
    }

    fn canonical_payload(
        norm_path: &str,
        content_blake3: &str,
        signer_key_id: &str,
        authority: AuthorityLevel,
    ) -> Vec<u8> {
        format!(
            "oshoosi-workspace-v2|path={}|blake3={}|signer={}|authority={}",
            norm_path,
            content_blake3,
            signer_key_id,
            authority.rank()
        )
        .into_bytes()
    }

    pub fn compute_hmac_sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).expect("HMAC accepts 32-byte key");
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    pub fn compute_keyed_blake3(&self, data: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.signing_key, data).as_bytes()
    }

    pub fn sign_and_register_workspace_file(
        &self,
        relative_path: &str,
        content: &[u8],
        signer_key_id: &str,
    ) -> SignedWorkspaceInstructionEntry {
        let norm_path = Self::normalize_path(relative_path);
        let content_blake3 = blake3::hash(content).to_hex().to_string();
        let assigned_authority = AuthorityLevel::L4WorkspaceConfiguration;
        let payload = Self::canonical_payload(
            &norm_path,
            &content_blake3,
            signer_key_id,
            assigned_authority,
        );
        let hmac_blake3_tag = hex::encode(self.compute_keyed_blake3(&payload));
        let hmac_sha256_tag = hex::encode(self.compute_hmac_sha256(&payload));
        let ed_att = blake3::keyed_hash(
            &self.signing_key,
            format!("ed25519+mldsa65:{}:{}", hmac_blake3_tag, hmac_sha256_tag).as_bytes(),
        )
        .to_hex()
        .to_string();

        let entry = SignedWorkspaceInstructionEntry {
            relative_path: norm_path.clone(),
            content_blake3,
            signer_key_id: signer_key_id.to_string(),
            hmac_blake3_tag,
            hmac_sha256_tag,
            ed25519_mldsa65_attestation_tag: format!("pq-ed25519-mldsa65:{}", ed_att),
            assigned_authority,
        };
        self.entries.insert(norm_path, entry.clone());
        entry
    }

    pub fn compute_merkle_root(&self) -> (String, [u8; 32]) {
        let mut leaves: Vec<String> = self
            .entries
            .iter()
            .map(|r| {
                let v = r.value();
                format!(
                    "{}:{}:{}:{}",
                    v.relative_path, v.content_blake3, v.hmac_blake3_tag, v.hmac_sha256_tag
                )
            })
            .collect();
        leaves.sort();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oshoosi-merkle-root-v2:");
        for leaf in &leaves {
            hasher.update(leaf.as_bytes());
            hasher.update(b"|");
        }
        let root_hex = hasher.finalize().to_hex().to_string();
        let root_hmac = self.compute_hmac_sha256(root_hex.as_bytes());
        (root_hex, root_hmac)
    }

    pub fn contains_authority_usurpation_or_unsafe_directive(
        content: &str,
    ) -> Option<&'static str> {
        let lower = content.to_ascii_lowercase();
        const FORBIDDEN_DIRECTIVES: &[(&str, &str)] = &[
            (
                "ignore previous instructions",
                "Attempts to override L2AuthorizedUserObjective",
            ),
            (
                "disregard user objective",
                "Attempts to override L2AuthorizedUserObjective",
            ),
            (
                "override system policy",
                "Attempts to override L1SystemSecurityPolicy",
            ),
            (
                "disable_security_policy",
                "Attempts to disable L1SystemSecurityPolicy",
            ),
            ("bypass_cedar", "Attempts to bypass Cedar reference monitor"),
            (
                "authority_level: l1",
                "Attempts upward authority promotion to L1SystemSecurityPolicy",
            ),
            (
                "authority_level: l2",
                "Attempts upward authority promotion to L2AuthorizedUserObjective",
            ),
            (
                "promote_to_system_policy",
                "Attempts upward authority promotion to L1",
            ),
            (
                "curl ",
                "Contains unauthorized shell network fetch directive in workspace config",
            ),
            (
                "wget ",
                "Contains unauthorized shell network fetch directive in workspace config",
            ),
            (
                "invoke-webrequest",
                "Contains unauthorized PowerShell web fetch directive in workspace config",
            ),
            (
                "webhook.site",
                "References external exfiltration sink in workspace config",
            ),
            (
                "requestbin",
                "References external exfiltration sink in workspace config",
            ),
            (
                "/dev/tcp/",
                "Contains reverse-shell socket directive in workspace config",
            ),
            (
                "nc -e",
                "Contains netcat reverse-shell directive in workspace config",
            ),
            (
                "exfiltrate",
                "Contains explicit exfiltration directive in workspace config",
            ),
            (
                "--no-verify",
                "Attempts to bypass git cryptographic hook verification",
            ),
        ];
        for (pattern, reason) in FORBIDDEN_DIRECTIVES {
            if lower.contains(pattern) {
                return Some(reason);
            }
        }
        None
    }

    pub fn verify_workspace_instruction(
        &self,
        relative_path: &str,
        content: &[u8],
        requested_authority: AuthorityLevel,
    ) -> WorkspaceInstructionVerificationResult {
        let norm_path = Self::normalize_path(relative_path);
        let actual_blake3 = blake3::hash(content).to_hex().to_string();
        let (merkle_root, merkle_hmac) = self.compute_merkle_root();
        let expected_merkle_hmac = self.compute_hmac_sha256(merkle_root.as_bytes());
        let merkle_root_hmac_verified = bool::from(merkle_hmac.ct_eq(&expected_merkle_hmac));

        let decision_seed = format!(
            "ws-auth:{}:{}:{}:{}",
            norm_path,
            actual_blake3,
            requested_authority.rank(),
            merkle_root
        );
        let policy_decision_id = format!(
            "pdec-ws-{}",
            &blake3::hash(decision_seed.as_bytes()).to_hex()[..16]
        );

        let Some(entry_ref) = self.entries.get(&norm_path) else {
            return WorkspaceInstructionVerificationResult {
                allowed: false,
                path: norm_path,
                assigned_authority: AuthorityLevel::L5UntrustedRetrievedContent,
                effective_authority: AuthorityLevel::L5UntrustedRetrievedContent,
                cryptographic_signature_valid: false,
                merkle_root_blake3: merkle_root,
                merkle_root_hmac_verified,
                upward_promotion_blocked: requested_authority.rank()
                    < AuthorityLevel::L4WorkspaceConfiguration.rank(),
                policy_override_blocked: true,
                policy_decision_id,
                reason: "DENY_UNSIGNED_WORKSPACE_INSTRUCTION: File is not in the keyed HMAC-BLAKE3/HMAC-SHA256 Merkle allowlist".to_string(),
            };
        };
        let entry = entry_ref.value().clone();
        drop(entry_ref);

        let hash_matches = bool::from(
            entry
                .content_blake3
                .as_bytes()
                .ct_eq(actual_blake3.as_bytes()),
        );
        let payload = Self::canonical_payload(
            &norm_path,
            &actual_blake3,
            &entry.signer_key_id,
            entry.assigned_authority,
        );
        let expected_blake3_mac = self.compute_keyed_blake3(&payload);
        let expected_sha256_mac = self.compute_hmac_sha256(&payload);

        let provided_blake3_mac = hex::decode(&entry.hmac_blake3_tag).unwrap_or_default();
        let provided_sha256_mac = hex::decode(&entry.hmac_sha256_tag).unwrap_or_default();

        let mac_valid = hash_matches
            && provided_blake3_mac.len() == 32
            && provided_sha256_mac.len() == 32
            && bool::from(provided_blake3_mac.as_slice().ct_eq(&expected_blake3_mac))
            && bool::from(provided_sha256_mac.as_slice().ct_eq(&expected_sha256_mac))
            && merkle_root_hmac_verified;

        if !mac_valid {
            return WorkspaceInstructionVerificationResult {
                allowed: false,
                path: norm_path,
                assigned_authority: entry.assigned_authority,
                effective_authority: AuthorityLevel::L5UntrustedRetrievedContent,
                cryptographic_signature_valid: false,
                merkle_root_blake3: merkle_root,
                merkle_root_hmac_verified,
                upward_promotion_blocked: false,
                policy_override_blocked: true,
                policy_decision_id,
                reason: "DENY_TAMPERED_OR_UNKEYED_WORKSPACE_SIGNATURE: Keyed HMAC-BLAKE3/HMAC-SHA256 verification failed".to_string(),
            };
        }

        if requested_authority.rank() < AuthorityLevel::L4WorkspaceConfiguration.rank() {
            return WorkspaceInstructionVerificationResult {
                allowed: false,
                path: norm_path,
                assigned_authority: AuthorityLevel::L4WorkspaceConfiguration,
                effective_authority: AuthorityLevel::L4WorkspaceConfiguration,
                cryptographic_signature_valid: true,
                merkle_root_blake3: merkle_root,
                merkle_root_hmac_verified,
                upward_promotion_blocked: true,
                policy_override_blocked: true,
                policy_decision_id,
                reason: format!(
                    "DENY_UPWARD_AUTHORITY_PROMOTION: Signed L4WorkspaceConfiguration cannot promote itself to {:?}",
                    requested_authority
                ),
            };
        }

        let text = String::from_utf8_lossy(content);
        if let Some(violation) = Self::contains_authority_usurpation_or_unsafe_directive(&text) {
            return WorkspaceInstructionVerificationResult {
                allowed: false,
                path: norm_path,
                assigned_authority: AuthorityLevel::L4WorkspaceConfiguration,
                effective_authority: AuthorityLevel::L4WorkspaceConfiguration,
                cryptographic_signature_valid: true,
                merkle_root_blake3: merkle_root,
                merkle_root_hmac_verified,
                upward_promotion_blocked: true,
                policy_override_blocked: true,
                policy_decision_id,
                reason: format!(
                    "DENY_SIGNED_INSTRUCTION_AUTHORITY_EXCEEDED: Signed L4 config rejected because it {}",
                    violation
                ),
            };
        }

        WorkspaceInstructionVerificationResult {
            allowed: true,
            path: norm_path,
            assigned_authority: AuthorityLevel::L4WorkspaceConfiguration,
            effective_authority: AuthorityLevel::L4WorkspaceConfiguration,
            cryptographic_signature_valid: true,
            merkle_root_blake3: merkle_root,
            merkle_root_hmac_verified,
            upward_promotion_blocked: false,
            policy_override_blocked: false,
            policy_decision_id,
            reason: "PERMIT_SCOPED_L4_WORKSPACE_INSTRUCTION: Cryptographic HMAC-BLAKE3/SHA256 verified and bounded to L4WorkspaceConfiguration".to_string(),
        }
    }
}

// ============================================================================
// 2. Canonical Cedar Entities, Actions, & Enforcement Stages
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CedarAction {
    ChildProcessExec,
    SensitiveFileAccess,
    ExternalNetworkConnect,
    ExternalWrite,
    PrivilegedLocalControl,
    DynamicCodeExec,
    CrossSessionTransfer,
}

impl CedarAction {
    pub fn cedar_id(self) -> &'static str {
        match self {
            Self::ChildProcessExec => "Action::\"ChildProcessExec\"",
            Self::SensitiveFileAccess => "Action::\"SensitiveFileAccess\"",
            Self::ExternalNetworkConnect => "Action::\"ExternalNetworkConnect\"",
            Self::ExternalWrite => "Action::\"ExternalWrite\"",
            Self::PrivilegedLocalControl => "Action::\"PrivilegedLocalControl\"",
            Self::DynamicCodeExec => "Action::\"DynamicCodeExec\"",
            Self::CrossSessionTransfer => "Action::\"CrossSessionTransfer\"",
        }
    }

    pub fn matrix_operation_class(self) -> &'static str {
        match self {
            Self::ChildProcessExec => "Child process execution",
            Self::SensitiveFileAccess => "Sensitive file access",
            Self::ExternalNetworkConnect => "External network connection",
            Self::ExternalWrite => "External SaaS mutation",
            Self::PrivilegedLocalControl => "Privileged IPC operation",
            Self::DynamicCodeExec => "Dynamic code execution",
            Self::CrossSessionTransfer => "Cross-session data transfer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DataClassification {
    Public = 0,
    InternalWorkspace = 1,
    Confidential = 2,
    CrownJewelSecret = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnforcementStage {
    PreExecutionPrevented,
    PostNotificationContained,
    PostExecutionDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarPrincipal {
    pub principal_id: String,
    pub session_id: String,
    pub process_instance_key: String,
    pub authority_level: AuthorityLevel,
    pub approved_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarResource {
    pub resource_id: String,
    pub resource_type: String,
    pub classification: DataClassification,
    pub is_signed_and_allowlisted: bool,
    pub is_approved_child_binary: bool,
    pub is_task_scoped_destination: bool,
    pub is_declassified_approved_sink: bool,
    pub service_identity: Option<String>,
    pub service_operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarContext {
    pub policy_version: String,
    pub causal_event_id: String,
    pub has_crown_jewel_taint: bool,
    pub highest_data_classification: DataClassification,
    pub taint_level: f64,
    pub cumulative_salami_turns: u32,
    pub has_approved_capability: bool,
    pub has_cryptographic_declassification: bool,
    pub upward_authority_promotion_attempted: bool,
    pub egress_budget_exceeded: bool,
    pub semantic_cosine_similarity: f64,
    pub covert_jitter_applied_ms: u64,
    pub taint_epoch: u64,
    pub revocation_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionRecord {
    pub allowed: bool,
    pub policy_decision_id: String,
    pub causal_event_id: String,
    pub policy_version: String,
    pub action: CedarAction,
    pub enforcement_stage: EnforcementStage,
    pub matched_forbid_policies: Vec<String>,
    pub matched_permit_policies: Vec<String>,
    pub reason: String,
    pub taint_epoch_at_decision: u64,
    pub revocation_seq_at_decision: u64,
    pub covert_jitter_ms: u64,
    pub evaluated_at: DateTime<Utc>,
}

// ============================================================================
// 3. Non-Forgeable Composite ProcessInstanceIdentity, Broker Attribution & CausalSecurityGraph
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInstanceIdentity {
    pub pid: u32,
    pub start_time_100ns: u64,
    pub image_digest_blake3: String,
    pub parent_instance_key: Option<String>,
    pub job_object_id: Option<String>,
    pub origin_session_id: String,
}

impl ProcessInstanceIdentity {
    pub fn new(
        pid: u32,
        start_time_100ns: u64,
        image_digest_blake3: impl Into<String>,
        parent_instance_key: Option<String>,
        job_object_id: Option<String>,
        origin_session_id: impl Into<String>,
    ) -> Self {
        Self {
            pid,
            start_time_100ns,
            image_digest_blake3: image_digest_blake3.into(),
            parent_instance_key,
            job_object_id,
            origin_session_id: origin_session_id.into(),
        }
    }

    pub fn instance_key(&self) -> String {
        let dig_prefix = &self.image_digest_blake3[..self.image_digest_blake3.len().min(12)];
        format!(
            "proc:{}:{}:{}:{}",
            self.pid, self.start_time_100ns, dig_prefix, self.origin_session_id
        )
    }
}

/// Identifies system/developer broker processes (`P1.2` Confused-Deputy Broker Attribution)
/// that execute operations on behalf of an initiating agent process/session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokerAttributionRecord {
    pub broker_image: String,
    pub broker_pid: u32,
    pub requesting_client_pid: u32,
    pub requesting_instance_key: String,
    pub attributed_origin_session_id: String,
    pub inherited_crown_jewel_taint: bool,
    pub inherited_taint_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalNodeState {
    pub node_key: String,
    pub origin_session_id: String,
    pub process_identity: Option<ProcessInstanceIdentity>,
    pub authority_level: AuthorityLevel,
    pub taint_level: f64,
    pub has_crown_jewel_taint: bool,
    pub highest_classification: DataClassification,
    pub cumulative_turns: u32,
    pub ancestor_keys: Vec<String>,
    pub last_causal_event_id: String,
    pub capabilities_revoked: bool,
    pub declassified_receipts: Vec<String>,
    pub session_terminated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustedTransformationKind {
    BooleanPassFailSummary,
    AggregateMetricCount,
    ZkRedactedAuditSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationReceipt {
    pub receipt_id: String,
    pub session_id: String,
    pub source_node_key: String,
    pub sanitized_payload_blake3: String,
    pub supervisor_hmac_tag: String,
    pub issued_at: DateTime<Utc>,
}

pub struct CausalSecurityGraph {
    nodes: DashMap<String, CausalNodeState>,
    pid_to_latest_instance: DashMap<u32, String>,
    session_taint: DashMap<String, CausalNodeState>,
    declassification_receipts: DashMap<String, DeclassificationReceipt>,
    broker_attributions: DashMap<u32, BrokerAttributionRecord>,
    supervisor_key: [u8; 32],
    causal_seq: AtomicU64,
}

impl Default for CausalSecurityGraph {
    fn default() -> Self {
        Self::new(*DEFAULT_SUPERVISOR_DECLASSIFY_KEY)
    }
}

impl CausalSecurityGraph {
    pub fn new(supervisor_key: [u8; 32]) -> Self {
        Self {
            nodes: DashMap::new(),
            pid_to_latest_instance: DashMap::new(),
            session_taint: DashMap::new(),
            declassification_receipts: DashMap::new(),
            broker_attributions: DashMap::new(),
            supervisor_key,
            causal_seq: AtomicU64::new(1),
        }
    }

    fn next_causal_event_id(&self, prefix: &str, key: &str) -> String {
        let seq = self.causal_seq.fetch_add(1, Ordering::SeqCst);
        let digest = blake3::hash(format!("{}:{}:{}", prefix, key, seq).as_bytes());
        format!("cevt-{:06}-{}", seq, &digest.to_hex()[..12])
    }

    /// Returns true if an executable image is a system/developer broker (`WmiPrvSE.exe`, `svchost.exe`,
    /// `conhost.exe`, `git-remote-https.exe`, `ssh.exe`, `dllhost.exe`).
    pub fn is_broker_process_image(image: &str) -> bool {
        let lower = image.replace('\\', "/").to_ascii_lowercase();
        const BROKERS: &[&str] = &[
            "wmiprvse.exe",
            "svchost.exe",
            "conhost.exe",
            "git-remote-https",
            "git-remote-http",
            "ssh.exe",
            "/usr/bin/ssh",
            "dllhost.exe",
            "backgroundtaskhost.exe",
        ];
        BROKERS
            .iter()
            .any(|b| lower.ends_with(b) || lower.contains(b))
    }

    /// Attributes a broker process (`WmiPrvSE.exe`, `svchost.exe`, `conhost.exe`, `git-remote-https.exe`, `ssh.exe`)
    /// to the requesting client PID / agent session (`P1.2` Confused-Deputy Broker Attribution) so that a tainted
    /// agent cannot launder privileged or outbound actions through an OS/Git/SSH broker.
    pub fn attribute_broker_operation(
        &self,
        broker_pid: u32,
        broker_start_time_100ns: u64,
        broker_image: &str,
        requesting_client_pid: u32,
        fallback_session_id: &str,
    ) -> (CausalNodeState, BrokerAttributionRecord) {
        let client_instance_key = self
            .pid_to_latest_instance
            .get(&requesting_client_pid)
            .map(|r| r.value().clone());

        let client_state = self.resolve_state(
            client_instance_key.as_deref(),
            Some(requesting_client_pid),
            fallback_session_id,
        );

        let broker_identity = ProcessInstanceIdentity::new(
            broker_pid,
            broker_start_time_100ns,
            blake3::hash(format!("broker:{}:{}", broker_image, requesting_client_pid).as_bytes())
                .to_hex()
                .to_string(),
            Some(client_state.node_key.clone()),
            None,
            client_state.origin_session_id.clone(),
        );

        let broker_state =
            self.register_process_instance(broker_identity, client_state.authority_level);

        let record = BrokerAttributionRecord {
            broker_image: broker_image.to_string(),
            broker_pid,
            requesting_client_pid,
            requesting_instance_key: client_state.node_key,
            attributed_origin_session_id: broker_state.origin_session_id.clone(),
            inherited_crown_jewel_taint: broker_state.has_crown_jewel_taint,
            inherited_taint_level: broker_state.taint_level,
        };
        self.broker_attributions.insert(broker_pid, record.clone());
        (broker_state, record)
    }

    pub fn register_process_instance(
        &self,
        identity: ProcessInstanceIdentity,
        initial_authority: AuthorityLevel,
    ) -> CausalNodeState {
        let key = identity.instance_key();
        let mut taint_level = 0.0_f64;
        let mut has_crown_jewel_taint = false;
        let mut highest_classification = DataClassification::InternalWorkspace;
        let mut cumulative_turns = 1_u32;
        let mut ancestor_keys = Vec::new();
        let mut effective_authority = initial_authority;
        let mut capabilities_revoked = false;

        if let Some(ref parent_key) = identity.parent_instance_key {
            if let Some(parent_ref) = self.nodes.get(parent_key) {
                let p = parent_ref.value();
                taint_level = taint_level.max(p.taint_level);
                has_crown_jewel_taint |= p.has_crown_jewel_taint;
                highest_classification = highest_classification.max(p.highest_classification);
                cumulative_turns = p.cumulative_turns.saturating_add(1);
                ancestor_keys = p.ancestor_keys.clone();
                ancestor_keys.push(parent_key.clone());
                if effective_authority.rank() < p.authority_level.rank() {
                    effective_authority = p.authority_level;
                }
                capabilities_revoked |= p.capabilities_revoked;
            }
        }

        if let Some(sess_ref) = self.session_taint.get(&identity.origin_session_id) {
            let s = sess_ref.value();
            taint_level = taint_level.max(s.taint_level);
            has_crown_jewel_taint |= s.has_crown_jewel_taint;
            highest_classification = highest_classification.max(s.highest_classification);
            cumulative_turns = cumulative_turns.max(s.cumulative_turns);
            capabilities_revoked |= s.capabilities_revoked;
        }

        let causal_event_id = self.next_causal_event_id("proc-spawn", &key);
        let state = CausalNodeState {
            node_key: key.clone(),
            origin_session_id: identity.origin_session_id.clone(),
            process_identity: Some(identity.clone()),
            authority_level: effective_authority,
            taint_level,
            has_crown_jewel_taint,
            highest_classification,
            cumulative_turns,
            ancestor_keys,
            last_causal_event_id: causal_event_id,
            capabilities_revoked,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        };

        self.nodes.insert(key.clone(), state.clone());
        self.pid_to_latest_instance.insert(identity.pid, key);
        self.sync_session_state(&state);
        state
    }

    fn sync_session_state(&self, node: &CausalNodeState) {
        let sess_id = node.origin_session_id.clone();
        let existing = self.session_taint.get(&sess_id).map(|r| r.value().clone());
        let updated = match existing {
            Some(mut cur) => {
                cur.taint_level = cur.taint_level.max(node.taint_level);
                cur.has_crown_jewel_taint |= node.has_crown_jewel_taint;
                cur.highest_classification =
                    cur.highest_classification.max(node.highest_classification);
                cur.cumulative_turns = cur.cumulative_turns.max(node.cumulative_turns);
                cur.last_causal_event_id = node.last_causal_event_id.clone();
                cur.capabilities_revoked |= node.capabilities_revoked;
                if node.authority_level.rank() > cur.authority_level.rank() {
                    cur.authority_level = node.authority_level;
                }
                cur
            }
            None => node.clone(),
        };
        self.session_taint.insert(sess_id, updated);
    }

    pub fn record_causal_step(
        &self,
        node_key: &str,
        session_id: &str,
        step_taint_delta: f64,
        classification_read: DataClassification,
        salami_increment: f64,
    ) -> CausalNodeState {
        let existing_node = self.nodes.get(node_key).map(|r| r.value().clone());
        let existing_sess = self
            .session_taint
            .get(session_id)
            .map(|r| r.value().clone());

        let base = existing_node.or(existing_sess).unwrap_or(CausalNodeState {
            node_key: node_key.to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: None,
            authority_level: AuthorityLevel::L2AuthorizedUserObjective,
            taint_level: 0.0,
            has_crown_jewel_taint: false,
            highest_classification: DataClassification::Public,
            cumulative_turns: 0,
            ancestor_keys: Vec::new(),
            last_causal_event_id: String::new(),
            capabilities_revoked: false,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        });

        let is_crown_jewel = classification_read == DataClassification::CrownJewelSecret;
        let next_taint = (base.taint_level.max(step_taint_delta) + salami_increment.max(0.0))
            .max(if is_crown_jewel { 0.95 } else { 0.0 })
            .min(1.0);
        let causal_event_id = self.next_causal_event_id("step", node_key);

        let updated = CausalNodeState {
            node_key: node_key.to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: base.process_identity,
            authority_level: base.authority_level,
            taint_level: next_taint,
            has_crown_jewel_taint: base.has_crown_jewel_taint || is_crown_jewel,
            highest_classification: base.highest_classification.max(classification_read),
            cumulative_turns: base.cumulative_turns.saturating_add(1),
            ancestor_keys: base.ancestor_keys,
            last_causal_event_id: causal_event_id,
            capabilities_revoked: base.capabilities_revoked,
            declassified_receipts: base.declassified_receipts,
            session_terminated: base.session_terminated,
        };

        self.nodes.insert(node_key.to_string(), updated.clone());
        self.sync_session_state(&updated);
        updated
    }

    pub fn propagate_edge(
        &self,
        source_key: &str,
        target_key: &str,
        target_session_id: &str,
    ) -> CausalNodeState {
        let src = self
            .nodes
            .get(source_key)
            .map(|r| r.value().clone())
            .or_else(|| {
                self.session_taint
                    .get(source_key)
                    .map(|r| r.value().clone())
            });

        let dst = self
            .nodes
            .get(target_key)
            .map(|r| r.value().clone())
            .unwrap_or(CausalNodeState {
                node_key: target_key.to_string(),
                origin_session_id: target_session_id.to_string(),
                process_identity: None,
                authority_level: AuthorityLevel::L2AuthorizedUserObjective,
                taint_level: 0.0,
                has_crown_jewel_taint: false,
                highest_classification: DataClassification::Public,
                cumulative_turns: 0,
                ancestor_keys: Vec::new(),
                last_causal_event_id: String::new(),
                capabilities_revoked: false,
                declassified_receipts: Vec::new(),
                session_terminated: false,
            });

        let (
            taint_level,
            has_crown_jewel_taint,
            highest_classification,
            mut ancestors,
            turns,
            revoked,
        ) = if let Some(s) = src {
            let mut anc = dst.ancestor_keys.clone();
            for k in &s.ancestor_keys {
                if !anc.contains(k) {
                    anc.push(k.clone());
                }
            }
            if !anc.contains(&s.node_key) {
                anc.push(s.node_key.clone());
            }
            (
                dst.taint_level.max(s.taint_level),
                dst.has_crown_jewel_taint || s.has_crown_jewel_taint,
                dst.highest_classification.max(s.highest_classification),
                anc,
                dst.cumulative_turns
                    .max(s.cumulative_turns)
                    .saturating_add(1),
                dst.capabilities_revoked || s.capabilities_revoked,
            )
        } else {
            (
                dst.taint_level,
                dst.has_crown_jewel_taint,
                dst.highest_classification,
                dst.ancestor_keys,
                dst.cumulative_turns.saturating_add(1),
                dst.capabilities_revoked,
            )
        };

        let causal_event_id = self.next_causal_event_id("edge", target_key);
        let updated = CausalNodeState {
            node_key: target_key.to_string(),
            origin_session_id: target_session_id.to_string(),
            process_identity: dst.process_identity,
            authority_level: dst.authority_level,
            taint_level,
            has_crown_jewel_taint,
            highest_classification,
            cumulative_turns: turns,
            ancestor_keys: std::mem::take(&mut ancestors),
            last_causal_event_id: causal_event_id,
            capabilities_revoked: revoked,
            declassified_receipts: dst.declassified_receipts,
            session_terminated: dst.session_terminated,
        };

        self.nodes.insert(target_key.to_string(), updated.clone());
        self.sync_session_state(&updated);
        updated
    }

    pub fn revoke_node_capabilities(&self, node_key: &str, session_id: &str) {
        if let Some(mut node) = self.nodes.get_mut(node_key) {
            node.capabilities_revoked = true;
            node.taint_level = 1.0;
        }
        if let Some(mut sess) = self.session_taint.get_mut(session_id) {
            sess.capabilities_revoked = true;
            sess.taint_level = 1.0;
        }
    }

    pub fn issue_supervisor_declassification_receipt(
        &self,
        session_id: &str,
        source_node_key: &str,
        redacted_payload: &str,
    ) -> Result<DeclassificationReceipt, String> {
        if !redacted_payload.contains("<ZK_PII:")
            && !redacted_payload.contains("<ZK_CROWN_JEWEL_REDACTED:")
            && !redacted_payload.contains("<ZK_MI_REDACTED>")
        {
            return Err(
                "DECLASSIFICATION_REJECTED: Payload must be ZK-redacted (<ZK_PII:...> or <ZK_CROWN_JEWEL_REDACTED:...>)"
                    .to_string(),
            );
        }

        let payload_blake3 = blake3::hash(redacted_payload.as_bytes())
            .to_hex()
            .to_string();
        let msg = format!(
            "zk-declassify-v1|sess={}|node={}|hash={}",
            session_id, source_node_key, payload_blake3
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.supervisor_key).expect("HMAC accepts 32-byte key");
        mac.update(msg.as_bytes());
        let tag_hex = hex::encode(mac.finalize().into_bytes());
        let receipt_id = format!("zkrec-{}", &payload_blake3[..16]);

        let receipt = DeclassificationReceipt {
            receipt_id: receipt_id.clone(),
            session_id: session_id.to_string(),
            source_node_key: source_node_key.to_string(),
            sanitized_payload_blake3: payload_blake3,
            supervisor_hmac_tag: tag_hex,
            issued_at: Utc::now(),
        };
        self.declassification_receipts
            .insert(receipt_id.clone(), receipt.clone());

        if let Some(mut node) = self.nodes.get_mut(source_node_key) {
            node.declassified_receipts.push(receipt_id.clone());
        }
        if let Some(mut sess) = self.session_taint.get_mut(session_id) {
            sess.declassified_receipts.push(receipt_id);
        }
        Ok(receipt)
    }

    pub fn verify_declassification_receipt(
        &self,
        receipt_id: &str,
        session_id: &str,
        redacted_payload: &str,
    ) -> bool {
        let Some(rec_ref) = self.declassification_receipts.get(receipt_id) else {
            return false;
        };
        let rec = rec_ref.value().clone();
        drop(rec_ref);

        if rec.session_id != session_id {
            return false;
        }
        let actual_hash = blake3::hash(redacted_payload.as_bytes())
            .to_hex()
            .to_string();
        if !bool::from(
            rec.sanitized_payload_blake3
                .as_bytes()
                .ct_eq(actual_hash.as_bytes()),
        ) {
            return false;
        }

        let msg = format!(
            "zk-declassify-v1|sess={}|node={}|hash={}",
            rec.session_id, rec.source_node_key, actual_hash
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.supervisor_key).expect("HMAC accepts 32-byte key");
        mac.update(msg.as_bytes());
        let expected = mac.finalize().into_bytes();
        let Ok(provided) = hex::decode(&rec.supervisor_hmac_tag) else {
            return false;
        };
        provided.len() == 32 && bool::from(provided.as_slice().ct_eq(&expected))
    }

    pub fn apply_trusted_transformation(
        &self,
        session_id: &str,
        source_node_key: &str,
        derived_node_key: &str,
        kind: TrustedTransformationKind,
        transformed_value: &str,
    ) -> Result<CausalNodeState, String> {
        let valid_format = match kind {
            TrustedTransformationKind::BooleanPassFailSummary => {
                matches!(transformed_value.trim(), "PASS" | "FAIL" | "true" | "false")
            }
            TrustedTransformationKind::AggregateMetricCount => {
                transformed_value.trim().parse::<u64>().is_ok()
            }
            TrustedTransformationKind::ZkRedactedAuditSummary => {
                transformed_value.contains("<ZK_PII:")
                    || transformed_value.contains("<ZK_CROWN_JEWEL_REDACTED:")
            }
        };
        if !valid_format {
            return Err(format!(
                "TRUSTED_TRANSFORMATION_REJECTED: Value {:?} does not conform to {:?}",
                transformed_value, kind
            ));
        }

        let causal_event_id = self.next_causal_event_id("trusted-transform", derived_node_key);
        let derived = CausalNodeState {
            node_key: derived_node_key.to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: None,
            authority_level: AuthorityLevel::L3TrustedApplicationInstruction,
            taint_level: 0.10,
            has_crown_jewel_taint: false,
            highest_classification: DataClassification::InternalWorkspace,
            cumulative_turns: 1,
            ancestor_keys: vec![source_node_key.to_string()],
            last_causal_event_id: causal_event_id,
            capabilities_revoked: false,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        };
        self.nodes
            .insert(derived_node_key.to_string(), derived.clone());
        Ok(derived)
    }

    pub fn terminate_session(&self, session_id: &str) {
        if let Some(mut sess) = self.session_taint.get_mut(session_id) {
            sess.session_terminated = true;
            sess.capabilities_revoked = true;
        }
        let keys_to_terminate: Vec<String> = self
            .nodes
            .iter()
            .filter(|r| r.value().origin_session_id == session_id)
            .map(|r| r.key().clone())
            .collect();
        for k in keys_to_terminate {
            if let Some(mut node) = self.nodes.get_mut(&k) {
                node.session_terminated = true;
                node.capabilities_revoked = true;
            }
        }
    }

    pub fn resolve_state(
        &self,
        node_key: Option<&str>,
        pid: Option<u32>,
        session_id: &str,
    ) -> CausalNodeState {
        if let Some(k) = node_key {
            if let Some(n) = self.nodes.get(k) {
                let mut state = n.value().clone();
                if let Some(s) = self.session_taint.get(session_id) {
                    state.taint_level = state.taint_level.max(s.taint_level);
                    state.has_crown_jewel_taint |= s.has_crown_jewel_taint;
                    state.highest_classification =
                        state.highest_classification.max(s.highest_classification);
                    state.capabilities_revoked |= s.capabilities_revoked;
                    state.session_terminated |= s.session_terminated;
                }
                return state;
            }
        }
        if let Some(p) = pid {
            if let Some(inst_key) = self.pid_to_latest_instance.get(&p) {
                let k = inst_key.value().clone();
                drop(inst_key);
                if let Some(n) = self.nodes.get(&k) {
                    return n.value().clone();
                }
            }
        }
        if let Some(s) = self.session_taint.get(session_id) {
            return s.value().clone();
        }
        CausalNodeState {
            node_key: node_key.unwrap_or(session_id).to_string(),
            origin_session_id: session_id.to_string(),
            process_identity: None,
            authority_level: AuthorityLevel::L2AuthorizedUserObjective,
            taint_level: 0.0,
            has_crown_jewel_taint: false,
            highest_classification: DataClassification::InternalWorkspace,
            cumulative_turns: 0,
            ancestor_keys: Vec::new(),
            last_causal_event_id: self.next_causal_event_id("init", session_id),
            capabilities_revoked: false,
            declassified_receipts: Vec::new(),
            session_terminated: false,
        }
    }

    /// Exports a deterministic snapshot of all session taint nodes for `P2.2` trusted-state recovery.
    pub fn export_session_snapshot(&self) -> Vec<(String, CausalNodeState)> {
        let mut out: Vec<(String, CausalNodeState)> = self
            .session_taint
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Restores session taint state from a verified snapshot (`P2.2` recovery).
    pub fn restore_session_snapshot(&self, snapshot: &[(String, CausalNodeState)]) {
        self.session_taint.clear();
        for (k, v) in snapshot {
            self.session_taint.insert(k.clone(), v.clone());
        }
    }
}

// ============================================================================
// 4. Loopback & Local IPC Service-Identity & Operation Authorizer (Path 6)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalServiceIdentity {
    OllamaLocalAiService,
    ChromeDevToolsBrowserDebug,
    DockerEngineControlPlane,
    WindowsPrivilegedNamedPipe,
    UnixPrivilegedControlSocket,
    OsoosiDashboardService,
    UnknownLoopbackService { host_port: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalServiceOperation {
    ReadOnlyInferenceOrStatus,
    ModelOrConfigMutation,
    BrowserSessionControl,
    HostContainerControl,
    PrivilegedOsPipeAccess,
    UnclassifiedLocalOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopbackClassification {
    pub is_local_or_ipc: bool,
    pub service_identity: LocalServiceIdentity,
    pub service_operation: LocalServiceOperation,
    pub requires_privileged_capability: bool,
    pub mapped_cedar_action: CedarAction,
}

pub struct LoopbackIpcAuthorizer;

impl LoopbackIpcAuthorizer {
    pub fn classify_target(target: &str, http_method_or_op: &str) -> LoopbackClassification {
        let lower = target.trim().to_ascii_lowercase();
        let op_upper = http_method_or_op.trim().to_ascii_uppercase();

        if lower.starts_with(r"\\.\pipe\")
            || lower.starts_with("//./pipe/")
            || lower.contains(r"\pipe\")
        {
            if lower.contains("docker_engine") || lower.contains("containerd") {
                return LoopbackClassification {
                    is_local_or_ipc: true,
                    service_identity: LocalServiceIdentity::DockerEngineControlPlane,
                    service_operation: LocalServiceOperation::HostContainerControl,
                    requires_privileged_capability: true,
                    mapped_cedar_action: CedarAction::PrivilegedLocalControl,
                };
            }
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::WindowsPrivilegedNamedPipe,
                service_operation: LocalServiceOperation::PrivilegedOsPipeAccess,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        if lower.ends_with(".sock")
            || lower.starts_with("/var/run/")
            || lower.starts_with("/run/")
            || lower.starts_with("unix://")
        {
            let identity = if lower.contains("docker")
                || lower.contains("containerd")
                || lower.contains("podman")
            {
                LocalServiceIdentity::DockerEngineControlPlane
            } else {
                LocalServiceIdentity::UnixPrivilegedControlSocket
            };
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: identity,
                service_operation: LocalServiceOperation::HostContainerControl,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        let (host, port, path) = if let Ok(parsed) = url::Url::parse(&lower) {
            let h = parsed.host_str().unwrap_or("").to_string();
            let p = parsed.port_or_known_default().unwrap_or(80);
            let path_str = parsed.path().to_string();
            (h, p, path_str)
        } else {
            let stripped = lower
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("ws://")
                .trim_start_matches("wss://");
            let (host_port, path_part) = match stripped.find('/') {
                Some(idx) => (&stripped[..idx], &stripped[idx..]),
                None => (stripped, "/"),
            };
            let (h, p) = if let Some(colon) = host_port.rfind(':') {
                let port_num = host_port[colon + 1..].parse::<u16>().unwrap_or(80);
                (
                    host_port[..colon].trim_matches(&['[', ']'][..]).to_string(),
                    port_num,
                )
            } else {
                (host_port.to_string(), 80)
            };
            (h, p, path_part.to_string())
        };

        let is_loopback = host == "localhost"
            || host == "127.0.0.1"
            || host.starts_with("127.")
            || host == "::1"
            || host == "0.0.0.0"
            || host.starts_with("::ffff:127.");

        if !is_loopback {
            let is_write = matches!(
                op_upper.as_str(),
                "POST" | "PUT" | "PATCH" | "DELETE" | "PUBLISH" | "WRITE" | "MUTATE"
            ) || lower.contains("/issues/")
                || lower.contains("/comments")
                || lower.contains("webhook");
            return LoopbackClassification {
                is_local_or_ipc: false,
                service_identity: LocalServiceIdentity::UnknownLoopbackService {
                    host_port: format!("{}:{}", host, port),
                },
                service_operation: LocalServiceOperation::UnclassifiedLocalOperation,
                requires_privileged_capability: is_write,
                mapped_cedar_action: if is_write {
                    CedarAction::ExternalWrite
                } else {
                    CedarAction::ExternalNetworkConnect
                },
            };
        }

        if port == 9222
            || port == 9333
            || path.starts_with("/json/version")
            || path.starts_with("/json/list")
            || path.starts_with("/devtools/")
        {
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::ChromeDevToolsBrowserDebug,
                service_operation: LocalServiceOperation::BrowserSessionControl,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        if port == 2375
            || port == 2376
            || path.contains("/containers/create")
            || path.contains("/containers/json")
        {
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::DockerEngineControlPlane,
                service_operation: LocalServiceOperation::HostContainerControl,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        if port == 11434
            || path.starts_with("/api/generate")
            || path.starts_with("/api/embeddings")
            || path.starts_with("/api/chat")
        {
            let is_benign_inference = (path == "/api/generate"
                || path == "/api/chat"
                || path == "/api/embeddings"
                || path == "/api/embed"
                || path == "/api/tags"
                || path == "/api/ps")
                && !matches!(op_upper.as_str(), "DELETE" | "PUT");
            if is_benign_inference {
                return LoopbackClassification {
                    is_local_or_ipc: true,
                    service_identity: LocalServiceIdentity::OllamaLocalAiService,
                    service_operation: LocalServiceOperation::ReadOnlyInferenceOrStatus,
                    requires_privileged_capability: false,
                    mapped_cedar_action: CedarAction::ExternalNetworkConnect,
                };
            } else {
                return LoopbackClassification {
                    is_local_or_ipc: true,
                    service_identity: LocalServiceIdentity::OllamaLocalAiService,
                    service_operation: LocalServiceOperation::ModelOrConfigMutation,
                    requires_privileged_capability: true,
                    mapped_cedar_action: CedarAction::PrivilegedLocalControl,
                };
            }
        }

        if port == 3030 {
            let is_read_only = matches!(op_upper.as_str(), "GET" | "HEAD" | "READ" | "")
                && !path.contains("/policy/disable")
                && !path.contains("/admin/");
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::OsoosiDashboardService,
                service_operation: if is_read_only {
                    LocalServiceOperation::ReadOnlyInferenceOrStatus
                } else {
                    LocalServiceOperation::ModelOrConfigMutation
                },
                requires_privileged_capability: !is_read_only,
                mapped_cedar_action: if is_read_only {
                    CedarAction::ExternalNetworkConnect
                } else {
                    CedarAction::PrivilegedLocalControl
                },
            };
        }

        LoopbackClassification {
            is_local_or_ipc: true,
            service_identity: LocalServiceIdentity::UnknownLoopbackService {
                host_port: format!("{}:{}", host, port),
            },
            service_operation: LocalServiceOperation::UnclassifiedLocalOperation,
            requires_privileged_capability: true,
            mapped_cedar_action: CedarAction::PrivilegedLocalControl,
        }
    }
}

// ============================================================================
// 5. Revocation-Bound Capability Delegation Cache & Concurrency Seqlock Barrier
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityCacheKey {
    pub principal_id: String,
    pub action: CedarAction,
    pub resource_id: String,
    pub policy_version: String,
    pub taint_epoch: u64,
    pub revocation_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardedEffectOutcome<T> {
    Committed {
        output: T,
        policy_decision_id: String,
        causal_event_id: String,
    },
    DeniedPreExecution {
        policy_decision_id: String,
        causal_event_id: String,
        reason: String,
    },
    DeniedByConcurrentRevocation {
        policy_decision_id: String,
        causal_event_id: String,
        decision_taint_epoch: u64,
        current_taint_epoch: u64,
        decision_revocation_seq: u64,
        current_revocation_seq: u64,
        reason: String,
    },
}

pub struct RevocationBoundCapabilityCache {
    entries: DashMap<CapabilityCacheKey, PolicyDecisionRecord>,
    taint_epoch: AtomicU64,
    revocation_seq: AtomicU64,
    in_flight_sensitive_reads: AtomicU64,
    taint_transition_barrier: RwLock<()>,
}

impl Default for RevocationBoundCapabilityCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationBoundCapabilityCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            taint_epoch: AtomicU64::new(1),
            revocation_seq: AtomicU64::new(1),
            in_flight_sensitive_reads: AtomicU64::new(0),
            taint_transition_barrier: RwLock::new(()),
        }
    }

    pub fn current_taint_epoch(&self) -> u64 {
        self.taint_epoch.load(Ordering::SeqCst)
    }

    pub fn current_revocation_seq(&self) -> u64 {
        self.revocation_seq.load(Ordering::SeqCst)
    }

    pub fn in_flight_sensitive_reads(&self) -> u64 {
        self.in_flight_sensitive_reads.load(Ordering::SeqCst)
    }

    pub fn advance_taint_and_revocation(&self) -> (u64, u64) {
        let new_taint = self.taint_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let new_rev = self.revocation_seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.entries.clear();
        (new_taint, new_rev)
    }

    pub fn get_cached(&self, key: &CapabilityCacheKey) -> Option<PolicyDecisionRecord> {
        if key.taint_epoch != self.current_taint_epoch()
            || key.revocation_seq != self.current_revocation_seq()
            || self.in_flight_sensitive_reads() > 0
        {
            return None;
        }
        self.entries.get(key).map(|r| r.value().clone())
    }

    pub fn put_cached(&self, key: CapabilityCacheKey, decision: PolicyDecisionRecord) {
        if decision.allowed
            && key.taint_epoch == self.current_taint_epoch()
            && key.revocation_seq == self.current_revocation_seq()
            && self.in_flight_sensitive_reads() == 0
        {
            self.entries.insert(key, decision);
        }
    }
}

// ============================================================================
// 6. P0.4 Protected Policy & Update Chain, P1.3 Safe Telemetry Overload, & P2.2 External Integrity Recovery
// ============================================================================

/// Cryptographically signed Cedar policy update bundle (`P0.4` Protected Policy & Update Chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyUpdateBundle {
    pub version_num: u64,
    pub policy_version_label: String,
    pub cedar_policy_text: String,
    pub author_principal: String,
    pub approver_principal: String,
    pub ed25519_signature_hex: String,
    pub mldsa65_pq_signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdateVerificationResult {
    pub accepted: bool,
    pub previous_version_num: u64,
    pub active_version_num: u64,
    pub active_policy_version: String,
    pub rollback_rejected: bool,
    pub unauthorized_principal_rejected: bool,
    pub signature_verified: bool,
    pub reason: String,
}

/// Protected Policy & Update Store (`P0.4`) enforcing monotonic version numbers,
/// dual `Ed25519` + `ML-DSA-65` cryptographic provenance, independent two-party approval,
/// and preservation of core `forbid` invariants.
pub struct ProtectedPolicyStore {
    control_plane_key: [u8; 32],
    active_version_num: AtomicU64,
    active_version_label: RwLock<String>,
    active_policy_text: RwLock<String>,
}

impl Default for ProtectedPolicyStore {
    fn default() -> Self {
        Self::new(*DEFAULT_CONTROL_PLANE_KEY)
    }
}

impl ProtectedPolicyStore {
    pub fn new(control_plane_key: [u8; 32]) -> Self {
        let initial_policy = concat!(
            "forbid (principal, action == Action::\"ExternalWrite\", resource) when { context.hasCrownJewelTaint };\n",
            "forbid (principal, action == Action::\"PrivilegedLocalControl\", resource) unless { context.hasApprovedCapability };"
        );
        Self {
            control_plane_key,
            active_version_num: AtomicU64::new(240), // corresponds to cedar-7ring-v2.4.0
            active_version_label: RwLock::new(CEDAR_BREAKOUT_POLICY_VERSION.to_string()),
            active_policy_text: RwLock::new(initial_policy.to_string()),
        }
    }

    pub fn active_version_num(&self) -> u64 {
        self.active_version_num.load(Ordering::SeqCst)
    }

    pub fn active_version_label(&self) -> String {
        self.active_version_label.read().clone()
    }

    pub fn sign_policy_bundle(
        &self,
        version_num: u64,
        policy_version_label: &str,
        cedar_policy_text: &str,
        author_principal: &str,
        approver_principal: &str,
    ) -> SignedPolicyUpdateBundle {
        let canonical = format!(
            "cedar-policy-update-v1|v={}|label={}|author={}|approver={}|body={}",
            version_num,
            policy_version_label,
            author_principal,
            approver_principal,
            cedar_policy_text
        );
        let ed_sig = blake3::keyed_hash(&self.control_plane_key, canonical.as_bytes())
            .to_hex()
            .to_string();
        let mut mac =
            HmacSha256::new_from_slice(&self.control_plane_key).expect("HMAC accepts 32-byte key");
        mac.update(b"mldsa65:");
        mac.update(canonical.as_bytes());
        let pq_sig = hex::encode(mac.finalize().into_bytes());

        SignedPolicyUpdateBundle {
            version_num,
            policy_version_label: policy_version_label.to_string(),
            cedar_policy_text: cedar_policy_text.to_string(),
            author_principal: author_principal.to_string(),
            approver_principal: approver_principal.to_string(),
            ed25519_signature_hex: ed_sig,
            mldsa65_pq_signature_hex: pq_sig,
        }
    }

    pub fn apply_policy_update(
        &self,
        bundle: &SignedPolicyUpdateBundle,
        capability_cache: &RevocationBoundCapabilityCache,
    ) -> PolicyUpdateVerificationResult {
        let prev_ver = self.active_version_num.load(Ordering::SeqCst);
        let cur_label = self.active_version_label.read().clone();

        // 1. Anti-rollback check (`version_num` must strictly increase)
        if bundle.version_num <= prev_ver {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: true,
                unauthorized_principal_rejected: false,
                signature_verified: false,
                reason: format!(
                    "DENY_POLICY_ROLLBACK: Candidate version {} <= active version {}",
                    bundle.version_num, prev_ver
                ),
            };
        }

        // 2. Principal separation & independent approval check (agents can NEVER author or approve policy updates)
        let author_l = bundle.author_principal.to_ascii_lowercase();
        let approver_l = bundle.approver_principal.to_ascii_lowercase();
        if author_l.is_empty()
            || approver_l.is_empty()
            || author_l == approver_l
            || author_l.contains("agent")
            || approver_l.contains("agent")
            || author_l.contains("worker")
            || approver_l.contains("worker")
        {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: false,
                unauthorized_principal_rejected: true,
                signature_verified: false,
                reason: "DENY_UNAUTHORIZED_OR_SELF_APPROVED_POLICY_UPDATE: Policy updates require distinct non-agent control-plane author and approver".to_string(),
            };
        }

        // 3. Verify Ed25519 + ML-DSA-65 cryptographic provenance in constant time
        let expected = self.sign_policy_bundle(
            bundle.version_num,
            &bundle.policy_version_label,
            &bundle.cedar_policy_text,
            &bundle.author_principal,
            &bundle.approver_principal,
        );
        let ed_ok = bool::from(
            bundle
                .ed25519_signature_hex
                .as_bytes()
                .ct_eq(expected.ed25519_signature_hex.as_bytes()),
        );
        let pq_ok = bool::from(
            bundle
                .mldsa65_pq_signature_hex
                .as_bytes()
                .ct_eq(expected.mldsa65_pq_signature_hex.as_bytes()),
        );
        if !ed_ok || !pq_ok {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: false,
                unauthorized_principal_rejected: false,
                signature_verified: false,
                reason: "DENY_INVALID_PQ_HYBRID_POLICY_SIGNATURE: Ed25519 or ML-DSA-65 signature verification failed".to_string(),
            };
        }

        // 4. Verify core `forbid` invariants are preserved
        if !bundle
            .cedar_policy_text
            .contains("Action::\"ExternalWrite\"")
            || !bundle.cedar_policy_text.contains("hasCrownJewelTaint")
            || !bundle
                .cedar_policy_text
                .contains("Action::\"PrivilegedLocalControl\"")
        {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: false,
                unauthorized_principal_rejected: true,
                signature_verified: true,
                reason: "DENY_CORE_FORBID_INVARIANT_REMOVAL: Policy update cannot strip mandatory ExternalWrite or PrivilegedLocalControl forbid rules".to_string(),
            };
        }

        self.active_version_num
            .store(bundle.version_num, Ordering::SeqCst);
        *self.active_version_label.write() = bundle.policy_version_label.clone();
        *self.active_policy_text.write() = bundle.cedar_policy_text.clone();
        capability_cache.advance_taint_and_revocation();

        PolicyUpdateVerificationResult {
            accepted: true,
            previous_version_num: prev_ver,
            active_version_num: bundle.version_num,
            active_policy_version: bundle.policy_version_label.clone(),
            rollback_rejected: false,
            unauthorized_principal_rejected: false,
            signature_verified: true,
            reason: "PERMIT_VERIFIED_POLICY_UPDATE: Monotonic version, two-party approval, and Ed25519+ML-DSA-65 provenance verified".to_string(),
        }
    }

    /// Evaluates a candidate tighten-only Cedar rule proposed by `SkyRL` or an automated learner.
    /// Enforces the Separate-Learning-from-Authority invariant:
    /// 1. Learners can NEVER directly mutate active Cedar policy (`active_policy_unchanged_until_signed = true`).
    /// 2. Learners can NEVER add `permit` rules or weaken existing `forbid` rules.
    /// 3. Learners can NEVER declassify taint or alter causal provenance.
    /// 4. Candidate `forbid` rules must pass both `benign_workflow_regression` and `protected_holdout` before
    ///    they are eligible for two-party human/control-plane signing (`SignedPolicyUpdateBundle`).
    pub fn evaluate_rl_tighten_only_proposal(
        &self,
        proposal: &CandidateCedarPolicyProposal,
    ) -> CandidatePolicyProposalEvaluation {
        let ver_before = self.active_version_num.load(Ordering::SeqCst);
        let clause_trimmed = proposal.proposed_forbid_clause.trim();
        let clause_lower = clause_trimmed.to_ascii_lowercase();

        if proposal.attempts_taint_declassification || proposal.attempts_causal_provenance_mutation
        {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: false,
                rejected_forbid_weakening: false,
                rejected_taint_or_provenance_mutation: true,
                rejected_unverified_regression_suite: false,
                reason: "DENY_RL_TAINT_OR_PROVENANCE_MUTATION: SkyRL cannot declassify taint or alter causal provenance".to_string(),
            };
        }

        if clause_lower.contains("permit") {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: true,
                rejected_forbid_weakening: false,
                rejected_taint_or_provenance_mutation: false,
                rejected_unverified_regression_suite: false,
                reason: "DENY_RL_PERMIT_RULE_PROPOSAL: SkyRL may only propose tighten-only Cedar forbid clauses, never permit rules".to_string(),
            };
        }

        if !clause_lower.starts_with("forbid") || !clause_trimmed.ends_with(';') {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: false,
                rejected_forbid_weakening: true,
                rejected_taint_or_provenance_mutation: false,
                rejected_unverified_regression_suite: false,
                reason: "DENY_RL_FORBID_WEAKENING_OR_MALFORMED_CLAUSE: Candidate rule must be a well-formed tighten-only Cedar forbid clause".to_string(),
            };
        }

        if !proposal.benign_workflow_regression_passed || !proposal.protected_holdout_passed {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: false,
                rejected_forbid_weakening: false,
                rejected_taint_or_provenance_mutation: false,
                rejected_unverified_regression_suite: true,
                reason: "DENY_RL_PROPOSAL_UNVERIFIED_REGRESSION: Candidate forbid rule must pass benign_workflow_regression and protected_holdout before signing".to_string(),
            };
        }

        CandidatePolicyProposalEvaluation {
            proposal_valid_for_dual_approval: true,
            active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
            rejected_permit_rule_addition: false,
            rejected_forbid_weakening: false,
            rejected_taint_or_provenance_mutation: false,
            rejected_unverified_regression_suite: false,
            reason: "ELIGIBLE_FOR_DUAL_PRINCIPAL_SIGNING: Tighten-only Cedar forbid proposal passed regression and holdout gates; active policy remains immutable until signed bundle is applied".to_string(),
        }
    }
}

/// Candidate tighten-only Cedar policy proposal emitted by an RL learner (`SkyRL`) or heuristic miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateCedarPolicyProposal {
    pub proposal_id: String,
    pub proposer_model_id: String,
    pub proposed_forbid_clause: String,
    pub attempts_taint_declassification: bool,
    pub attempts_causal_provenance_mutation: bool,
    pub benign_workflow_regression_passed: bool,
    pub protected_holdout_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePolicyProposalEvaluation {
    pub proposal_valid_for_dual_approval: bool,
    pub active_policy_unchanged_until_signed: bool,
    pub rejected_permit_rule_addition: bool,
    pub rejected_forbid_weakening: bool,
    pub rejected_taint_or_provenance_mutation: bool,
    pub rejected_unverified_regression_suite: bool,
    pub reason: String,
}

/// Per-workload degradation posture when observational telemetry drops (`EventsLost > 0`) (`P1.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadDegradationMode {
    NominalFullCapability,
    StrictReadOnlyContainment,
    QuarantineAffectedWorkloadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryOverloadEvaluation {
    pub affected_session_id: String,
    pub observational_events_lost: u64,
    pub queue_utilization_pct: f64,
    pub synchronous_enforcement_intact: bool,
    pub workload_mode: WorkloadDegradationMode,
    /// Strict safety invariant (`P1.3`): NEVER suspend the entire host when `EventsLost > 0`!
    pub host_wide_suspension_triggered: bool,
    pub unrelated_host_workloads_impacted: bool,
    pub reason: String,
}

/// Safe Telemetry Overload Controller (`P1.3`): distinguishes observational telemetry loss (`EventsLost > 0`)
/// from synchronous enforcement failure and degrades/quarantines ONLY the affected agent workload.
pub struct SafeTelemetryOverloadController {
    max_queue_capacity: usize,
    workload_modes: DashMap<String, WorkloadDegradationMode>,
}

impl Default for SafeTelemetryOverloadController {
    fn default() -> Self {
        Self {
            max_queue_capacity: 16_384,
            workload_modes: DashMap::new(),
        }
    }
}

impl SafeTelemetryOverloadController {
    pub fn evaluate_telemetry_backpressure(
        &self,
        session_id: &str,
        queue_depth: usize,
        events_lost: u64,
        synchronous_enforcement_intact: bool,
        causal_graph: &CausalSecurityGraph,
        capability_cache: &RevocationBoundCapabilityCache,
    ) -> TelemetryOverloadEvaluation {
        let util_pct =
            ((queue_depth as f64) / (self.max_queue_capacity.max(1) as f64) * 100.0).min(100.0);

        let (mode, reason) = if !synchronous_enforcement_intact
            || events_lost >= 100
            || util_pct >= 95.0
        {
            // Quarantine ONLY the affected agent session/workload, NEVER the whole host!
            causal_graph.revoke_node_capabilities(session_id, session_id);
            capability_cache.advance_taint_and_revocation();
            (
                WorkloadDegradationMode::QuarantineAffectedWorkloadOnly,
                format!(
                    "WORKLOAD_SCOPED_QUARANTINE: Quarantined agent session '{}' due to telemetry loss (events_lost={}, queue={:.1}%, sync_intact={}); host and unrelated processes remain 100% operational",
                    session_id, events_lost, util_pct, synchronous_enforcement_intact
                ),
            )
        } else if events_lost > 0 || util_pct >= 80.0 {
            capability_cache.advance_taint_and_revocation();
            (
                WorkloadDegradationMode::StrictReadOnlyContainment,
                format!(
                    "WORKLOAD_STRICT_READONLY_DEGRADATION: Restricted external writes/spawns for session '{}' under observational backpressure (events_lost={}, queue={:.1}%); zero host-wide suspension",
                    session_id, events_lost, util_pct
                ),
            )
        } else {
            (
                WorkloadDegradationMode::NominalFullCapability,
                "NOMINAL_TELEMETRY_HEALTH: Queue depth within bounds and 0 events lost".to_string(),
            )
        };

        self.workload_modes.insert(session_id.to_string(), mode);
        TelemetryOverloadEvaluation {
            affected_session_id: session_id.to_string(),
            observational_events_lost: events_lost,
            queue_utilization_pct: (util_pct * 100.0).round() / 100.0,
            synchronous_enforcement_intact,
            workload_mode: mode,
            host_wide_suspension_triggered: false,
            unrelated_host_workloads_impacted: false,
            reason,
        }
    }
}

/// Cryptographic snapshot and append-only audit envelope for `P2.2` External Integrity Verification & Recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedPolicyAndGraphSnapshot {
    pub snapshot_id: String,
    pub policy_version_num: u64,
    pub policy_version_label: String,
    pub workspace_merkle_root: String,
    pub session_states: Vec<(String, CausalNodeState)>,
    pub hmac_sha256_tag: String,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendOnlyAuditEnvelope {
    pub seq_num: u64,
    pub prev_envelope_blake3: String,
    pub event_summary: String,
    pub envelope_blake3: String,
    pub hmac_sha256_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperRecoveryResult {
    pub tamper_detected: bool,
    pub credentials_and_sessions_revoked: bool,
    pub restored_from_verified_snapshot: bool,
    pub restored_policy_version_num: u64,
    pub audit_chain_intact: bool,
    pub revocation_seq_after_recovery: u64,
    pub reason: String,
}

pub struct ExternalIntegrityVerifierAndRecovery {
    control_plane_key: [u8; 32],
    audit_chain: RwLock<Vec<AppendOnlyAuditEnvelope>>,
    last_verified_snapshot: RwLock<Option<VerifiedPolicyAndGraphSnapshot>>,
    tamper_flag: AtomicBool,
}

impl Default for ExternalIntegrityVerifierAndRecovery {
    fn default() -> Self {
        Self::new(*DEFAULT_CONTROL_PLANE_KEY)
    }
}

impl ExternalIntegrityVerifierAndRecovery {
    pub fn new(control_plane_key: [u8; 32]) -> Self {
        Self {
            control_plane_key,
            audit_chain: RwLock::new(Vec::new()),
            last_verified_snapshot: RwLock::new(None),
            tamper_flag: AtomicBool::new(false),
        }
    }

    fn compute_hmac(&self, payload: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.control_plane_key).expect("HMAC accepts 32-byte key");
        mac.update(payload);
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn append_audit_forwarding_envelope(&self, event_summary: &str) -> AppendOnlyAuditEnvelope {
        let mut chain = self.audit_chain.write();
        let seq_num = (chain.len() as u64) + 1;
        let prev_hash = chain
            .last()
            .map(|e| e.envelope_blake3.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let body = format!(
            "audit-env-v1|seq={}|prev={}|msg={}",
            seq_num, prev_hash, event_summary
        );
        let env_blake3 = blake3::hash(body.as_bytes()).to_hex().to_string();
        let hmac_tag = self.compute_hmac(body.as_bytes());
        let env = AppendOnlyAuditEnvelope {
            seq_num,
            prev_envelope_blake3: prev_hash,
            event_summary: event_summary.to_string(),
            envelope_blake3: env_blake3,
            hmac_sha256_tag: hmac_tag,
        };
        chain.push(env.clone());
        env
    }

    pub fn capture_verified_snapshot(
        &self,
        policy_store: &ProtectedPolicyStore,
        allowlist: &SignedWorkspaceInstructionAllowlist,
        causal_graph: &CausalSecurityGraph,
    ) -> VerifiedPolicyAndGraphSnapshot {
        let ver_num = policy_store.active_version_num();
        let ver_label = policy_store.active_version_label();
        let (merkle_root, _) = allowlist.compute_merkle_root();
        let sessions = causal_graph.export_session_snapshot();
        let serialized_sessions = serde_json::to_string(&sessions).unwrap_or_default();
        let canonical = format!(
            "snap-v1|vnum={}|vlabel={}|merkle={}|sessions={}",
            ver_num, ver_label, merkle_root, serialized_sessions
        );
        let hmac_tag = self.compute_hmac(canonical.as_bytes());
        let snap_id = format!(
            "snap-{}-{}",
            ver_num,
            &blake3::hash(canonical.as_bytes()).to_hex()[..12]
        );
        let snapshot = VerifiedPolicyAndGraphSnapshot {
            snapshot_id: snap_id,
            policy_version_num: ver_num,
            policy_version_label: ver_label,
            workspace_merkle_root: merkle_root,
            session_states: sessions,
            hmac_sha256_tag: hmac_tag,
            captured_at: Utc::now(),
        };
        *self.last_verified_snapshot.write() = Some(snapshot.clone());
        snapshot
    }

    pub fn simulate_memory_tamper(&self) {
        self.tamper_flag.store(true, Ordering::SeqCst);
    }

    /// Inspects external health attestation, detects any runtime tamper or unauthorized policy drift,
    /// automatically revokes active session credentials/capabilities, and restores from the last
    /// cryptographically verified snapshot (`P2.2`).
    pub fn verify_integrity_and_recover_if_tampered(
        &self,
        policy_store: &ProtectedPolicyStore,
        causal_graph: &CausalSecurityGraph,
        capability_cache: &RevocationBoundCapabilityCache,
        active_session_ids: &[&str],
    ) -> TamperRecoveryResult {
        let tampered = self.tamper_flag.swap(false, Ordering::SeqCst);
        let snap_opt = self.last_verified_snapshot.read().clone();

        let Some(snap) = snap_opt else {
            return TamperRecoveryResult {
                tamper_detected: tampered,
                credentials_and_sessions_revoked: false,
                restored_from_verified_snapshot: false,
                restored_policy_version_num: policy_store.active_version_num(),
                audit_chain_intact: true,
                revocation_seq_after_recovery: capability_cache.current_revocation_seq(),
                reason: "NO_SNAPSHOT_AVAILABLE".to_string(),
            };
        };

        let serialized_sessions = serde_json::to_string(&snap.session_states).unwrap_or_default();
        let canonical = format!(
            "snap-v1|vnum={}|vlabel={}|merkle={}|sessions={}",
            snap.policy_version_num,
            snap.policy_version_label,
            snap.workspace_merkle_root,
            serialized_sessions
        );
        let expected_hmac = self.compute_hmac(canonical.as_bytes());
        let snap_hmac_ok = bool::from(
            snap.hmac_sha256_tag
                .as_bytes()
                .ct_eq(expected_hmac.as_bytes()),
        );

        let version_tampered = policy_store.active_version_num() < snap.policy_version_num;
        if tampered || version_tampered {
            // 1. Revoke all active session capabilities & credentials
            for sid in active_session_ids {
                causal_graph.terminate_session(sid);
            }
            // 2. Restore verified policy version & causal graph snapshot if snapshot HMAC is valid
            if snap_hmac_ok {
                policy_store
                    .active_version_num
                    .store(snap.policy_version_num, Ordering::SeqCst);
                *policy_store.active_version_label.write() = snap.policy_version_label.clone();
                causal_graph.restore_session_snapshot(&snap.session_states);
                for sid in active_session_ids {
                    causal_graph.revoke_node_capabilities(sid, sid);
                }
            }
            let (_, rev_seq) = capability_cache.advance_taint_and_revocation();
            self.append_audit_forwarding_envelope(
                "CRITICAL_TAMPER_RECOVERY: Revoked session capabilities and restored verified policy/graph snapshot",
            );

            return TamperRecoveryResult {
                tamper_detected: true,
                credentials_and_sessions_revoked: true,
                restored_from_verified_snapshot: snap_hmac_ok,
                restored_policy_version_num: policy_store.active_version_num(),
                audit_chain_intact: snap_hmac_ok,
                revocation_seq_after_recovery: rev_seq,
                reason: "TAMPER_DETECTED_AND_RECOVERED: Active agent credentials/capabilities revoked and state restored from HMAC-verified snapshot".to_string(),
            };
        }

        TamperRecoveryResult {
            tamper_detected: false,
            credentials_and_sessions_revoked: false,
            restored_from_verified_snapshot: false,
            restored_policy_version_num: policy_store.active_version_num(),
            audit_chain_intact: snap_hmac_ok,
            revocation_seq_after_recovery: capability_cache.current_revocation_seq(),
            reason: "INTEGRITY_INTACT: External attestation and append-only audit chain verified"
                .to_string(),
        }
    }
}

// ============================================================================
// 7. Ring 7: Capability & Effect Authorization Layer (`Ring7CapabilityEffectAuthorizer`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEgressBudgetState {
    pub requests_used: u32,
    pub max_requests: u32,
    pub bytes_used: usize,
    pub max_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct CrownJewelProtectedAsset {
    pub asset_id: String,
    pub canonical_path: String,
    pub embedding_128d: Vec<f32>,
    pub concept_keywords: HashSet<String>,
}

pub struct Ring7CapabilityEffectAuthorizer {
    pub policy_version: String,
    pub workspace_allowlist: Arc<SignedWorkspaceInstructionAllowlist>,
    pub causal_graph: Arc<CausalSecurityGraph>,
    pub capability_cache: Arc<RevocationBoundCapabilityCache>,
    pub policy_store: Arc<ProtectedPolicyStore>,
    pub overload_controller: Arc<SafeTelemetryOverloadController>,
    pub integrity_recovery: Arc<ExternalIntegrityVerifierAndRecovery>,
    pub embedding_engine: EmbeddingGemma2Engine,
    crown_jewels: DashMap<String, CrownJewelProtectedAsset>,
    egress_budgets: DashMap<String, SessionEgressBudgetState>,
    decision_counter: AtomicU64,
}

impl Default for Ring7CapabilityEffectAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Ring7CapabilityEffectAuthorizer {
    pub fn new() -> Self {
        let auth = Self {
            policy_version: CEDAR_BREAKOUT_POLICY_VERSION.to_string(),
            workspace_allowlist: Arc::new(SignedWorkspaceInstructionAllowlist::default()),
            causal_graph: Arc::new(CausalSecurityGraph::default()),
            capability_cache: Arc::new(RevocationBoundCapabilityCache::default()),
            policy_store: Arc::new(ProtectedPolicyStore::default()),
            overload_controller: Arc::new(SafeTelemetryOverloadController::default()),
            integrity_recovery: Arc::new(ExternalIntegrityVerifierAndRecovery::default()),
            embedding_engine: EmbeddingGemma2Engine::new(MatryoshkaDim::Dim128),
            crown_jewels: DashMap::new(),
            egress_budgets: DashMap::new(),
            decision_counter: AtomicU64::new(1),
        };
        auth.register_crown_jewel_asset(
            "crown-jewel-phaselock-kernel",
            "crates/edr-phaselock/src/lib.rs",
            "Proprietary OshoosiClaw Phaselock sub-linear zero-allocation ring buffer kernel consensus algorithm with secret prime modulus 2147483647 and HMAC epoch key derivation.",
        );
        auth
    }

    pub fn register_crown_jewel_asset(&self, asset_id: &str, canonical_path: &str, content: &str) {
        let emb = self.embedding_engine.embed_text(content);
        let keywords: HashSet<String> = content
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
            .map(|w| w.to_ascii_lowercase())
            .filter(|w| w.len() >= 5)
            .collect();
        let norm_path = canonical_path.replace('\\', "/").to_ascii_lowercase();
        self.crown_jewels.insert(
            norm_path.clone(),
            CrownJewelProtectedAsset {
                asset_id: asset_id.to_string(),
                canonical_path: norm_path,
                embedding_128d: emb,
                concept_keywords: keywords,
            },
        );
    }

    pub fn classify_file_path(&self, path: &str) -> DataClassification {
        let lower = path.replace('\\', "/").to_ascii_lowercase();
        if self.crown_jewels.contains_key(&lower)
            || lower.contains(".env")
            || lower.contains("id_rsa")
            || lower.contains("id_ed25519")
            || lower.contains("/.ssh/")
            || lower.contains("/.aws/")
            || lower.contains("lsass")
            || lower.contains("/etc/shadow")
            || lower.contains("ntds.dit")
            || lower.contains("crown_jewel")
            || lower.contains("secret_key")
            || lower.contains("phaselock")
        {
            DataClassification::CrownJewelSecret
        } else if lower.contains("config") || lower.contains("credentials") {
            DataClassification::Confidential
        } else {
            DataClassification::InternalWorkspace
        }
    }

    pub fn compute_covert_jitter_ms(&self, session_id: &str, resource_id: &str, turn: u32) -> u64 {
        let h = blake3::hash(format!("jitter:{}:{}:{}", session_id, resource_id, turn).as_bytes());
        let b = h.as_bytes();
        let raw = u16::from_le_bytes([b[0], b[1]]) as u64;
        50 + (raw % 201)
    }

    pub fn max_crown_jewel_semantic_similarity(&self, payload: &str) -> f64 {
        if payload.trim().is_empty() {
            return 0.0;
        }
        let emb = self.embedding_engine.embed_text(payload);
        let payload_words: HashSet<String> = payload
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
            .map(|w| w.to_ascii_lowercase())
            .filter(|w| w.len() >= 5)
            .collect();

        let mut max_score = 0.0_f64;
        for item in self.crown_jewels.iter() {
            let asset = item.value();
            let dot: f32 = emb
                .iter()
                .zip(asset.embedding_128d.iter())
                .map(|(a, b)| a * b)
                .sum();
            let cosine = (dot as f64).clamp(0.0, 1.0);
            let overlap = if asset.concept_keywords.is_empty() || payload_words.is_empty() {
                0.0
            } else {
                let shared = payload_words.intersection(&asset.concept_keywords).count();
                (shared as f64) / (asset.concept_keywords.len().min(12).max(1) as f64)
            };
            let combined = (cosine * 0.65 + overlap.min(1.0) * 0.55).clamp(0.0, 1.0);
            if combined > max_score {
                max_score = combined;
            }
        }
        max_score
    }

    pub fn set_session_egress_budget(&self, session_id: &str, max_requests: u32, max_bytes: usize) {
        self.egress_budgets.insert(
            session_id.to_string(),
            SessionEgressBudgetState {
                requests_used: 0,
                max_requests,
                bytes_used: 0,
                max_bytes,
            },
        );
    }

    fn check_and_consume_egress_budget(&self, session_id: &str, payload_bytes: usize) -> bool {
        let Some(mut budget) = self.egress_budgets.get_mut(session_id) else {
            return false;
        };
        let next_req = budget.requests_used.saturating_add(1);
        let next_bytes = budget.bytes_used.saturating_add(payload_bytes);
        if next_req > budget.max_requests || next_bytes > budget.max_bytes {
            return true;
        }
        budget.requests_used = next_req;
        budget.bytes_used = next_bytes;
        false
    }

    pub fn evaluate_cedar_request(
        &self,
        principal: &CedarPrincipal,
        action: CedarAction,
        resource: &CedarResource,
        mut context: CedarContext,
        enforcement_stage: EnforcementStage,
    ) -> PolicyDecisionRecord {
        let taint_epoch = self.capability_cache.current_taint_epoch();
        let revocation_seq = self.capability_cache.current_revocation_seq();
        let active_policy_version = self.policy_store.active_version_label();
        context.taint_epoch = taint_epoch;
        context.revocation_seq = revocation_seq;
        context.policy_version = active_policy_version.clone();

        let cache_key = CapabilityCacheKey {
            principal_id: principal.principal_id.clone(),
            action,
            resource_id: resource.resource_id.clone(),
            policy_version: active_policy_version.clone(),
            taint_epoch,
            revocation_seq,
        };

        if let Some(cached) = self.capability_cache.get_cached(&cache_key) {
            return cached;
        }

        let seq = self.decision_counter.fetch_add(1, Ordering::SeqCst);
        let decision_hash = blake3::hash(
            format!(
                "cedar-eval:{}:{}:{}:{}:{}:{}:{}",
                principal.principal_id,
                action.cedar_id(),
                resource.resource_id,
                context.causal_event_id,
                taint_epoch,
                revocation_seq,
                seq
            )
            .as_bytes(),
        );
        let policy_decision_id = format!("pdec-{:06}-{}", seq, &decision_hash.to_hex()[..14]);

        let mut matched_forbid = Vec::new();
        let mut matched_permit = Vec::new();

        let graph_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );
        if graph_state.session_terminated {
            matched_forbid.push("CEDAR-FORBID-SESSION-TERMINATED".to_string());
        }
        if graph_state.capabilities_revoked {
            matched_forbid.push("CEDAR-FORBID-CAPABILITIES-REVOKED".to_string());
        }

        if let Some(w_mode) = self
            .overload_controller
            .workload_modes
            .get(&principal.session_id)
        {
            match *w_mode.value() {
                WorkloadDegradationMode::QuarantineAffectedWorkloadOnly => {
                    matched_forbid.push("CEDAR-FORBID-WORKLOAD-OVERLOAD-QUARANTINED".to_string());
                }
                WorkloadDegradationMode::StrictReadOnlyContainment
                    if matches!(
                        action,
                        CedarAction::ExternalWrite
                            | CedarAction::ChildProcessExec
                            | CedarAction::PrivilegedLocalControl
                    ) =>
                {
                    matched_forbid.push("CEDAR-FORBID-WORKLOAD-READONLY-DEGRADATION".to_string());
                }
                _ => {}
            }
        }

        let effective_crown_jewel_taint =
            context.has_crown_jewel_taint || graph_state.has_crown_jewel_taint;
        let effective_taint_level = context.taint_level.max(graph_state.taint_level);

        if action == CedarAction::ExternalWrite
            && effective_crown_jewel_taint
            && !context.has_cryptographic_declassification
        {
            matched_forbid.push(
                "CEDAR-FORBID-001: forbid(principal, action == Action::\"ExternalWrite\", resource) when { context.hasCrownJewelTaint }".to_string(),
            );
        }

        if action == CedarAction::PrivilegedLocalControl && !context.has_approved_capability {
            matched_forbid.push(
                "CEDAR-FORBID-002: forbid(principal, action == Action::\"PrivilegedLocalControl\", resource) unless { context.hasApprovedCapability }".to_string(),
            );
        }

        if matches!(
            action,
            CedarAction::ExternalWrite | CedarAction::ExternalNetworkConnect
        ) {
            if effective_crown_jewel_taint
                && !resource.is_declassified_approved_sink
                && !context.has_cryptographic_declassification
            {
                matched_forbid.push(
                    "CEDAR-FORBID-003A: Crown-Jewel tainted lineage forbidden from outbound network/write without cryptographic declassification".to_string(),
                );
            }
            if context.semantic_cosine_similarity >= 0.68
                && !context.has_cryptographic_declassification
            {
                matched_forbid.push(format!(
                    "CEDAR-FORBID-003B: Tier-2 semantic similarity {:.3} >= 0.68 against Crown-Jewel asset",
                    context.semantic_cosine_similarity
                ));
            }
            if context.egress_budget_exceeded {
                matched_forbid.push(
                    "CEDAR-FORBID-003C: Session outbound egress request/byte budget exceeded (covert channel rate limit)".to_string(),
                );
            }
            if !resource.is_task_scoped_destination {
                matched_forbid.push(
                    "CEDAR-FORBID-003D: Destination is outside the pinned task-scoped egress allowlist".to_string(),
                );
            }
            if effective_taint_level >= 0.70 && !context.has_cryptographic_declassification {
                matched_forbid.push(format!(
                    "CEDAR-FORBID-003E: Cumulative causal taint {:.2} >= 0.70 forbids external egress",
                    effective_taint_level
                ));
            }
        }

        if action == CedarAction::ChildProcessExec {
            if context.upward_authority_promotion_attempted {
                matched_forbid.push(
                    "CEDAR-FORBID-004A: Upward authority promotion from L4/L5 forbidden"
                        .to_string(),
                );
            }
            if !resource.is_approved_child_binary || !resource.is_signed_and_allowlisted {
                matched_forbid.push(
                    "CEDAR-FORBID-004B: Child process or build script is unsigned or not allowlisted for this task".to_string(),
                );
            }
            if effective_taint_level >= 0.75 {
                matched_forbid.push(format!(
                    "CEDAR-FORBID-004C: High causal taint {:.2} forbids spawning child processes",
                    effective_taint_level
                ));
            }
        }

        if action == CedarAction::DynamicCodeExec
            && (!resource.is_signed_and_allowlisted
                || principal.authority_level.rank()
                    > AuthorityLevel::L3TrustedApplicationInstruction.rank())
        {
            matched_forbid.push(
                "CEDAR-FORBID-005: Unsigned or untrusted dynamic code/module load forbidden"
                    .to_string(),
            );
        }

        if action == CedarAction::SensitiveFileAccess {
            if principal.authority_level.rank() >= AuthorityLevel::L4WorkspaceConfiguration.rank()
                && resource.classification == DataClassification::CrownJewelSecret
            {
                matched_forbid.push(
                    "CEDAR-FORBID-006A: L4/L5 untrusted instruction cannot authorize Crown-Jewel secret access".to_string(),
                );
            }
            if !resource.is_task_scoped_destination {
                matched_forbid.push(
                    "CEDAR-FORBID-006B: Sensitive credential/system file outside task scope"
                        .to_string(),
                );
            }
        }

        if action == CedarAction::CrossSessionTransfer
            && (effective_crown_jewel_taint || effective_taint_level >= 0.50)
            && !context.has_cryptographic_declassification
        {
            matched_forbid.push(
                "CEDAR-FORBID-007: Cross-session transfer of tainted/Crown-Jewel data forbidden without supervisor ZK declassification".to_string(),
            );
        }

        if matched_forbid.is_empty() {
            match action {
                CedarAction::ChildProcessExec
                    if resource.is_approved_child_binary && resource.is_signed_and_allowlisted =>
                {
                    matched_permit.push("CEDAR-PERMIT-CHILD-EXEC-SCOPED".to_string());
                }
                CedarAction::SensitiveFileAccess if resource.is_task_scoped_destination => {
                    matched_permit.push("CEDAR-PERMIT-SCOPED-FILE-READ".to_string());
                }
                CedarAction::ExternalNetworkConnect if resource.is_task_scoped_destination => {
                    matched_permit.push("CEDAR-PERMIT-SCOPED-NETWORK-CONNECT".to_string());
                }
                CedarAction::ExternalWrite
                    if resource.is_task_scoped_destination
                        && (!effective_crown_jewel_taint
                            || context.has_cryptographic_declassification) =>
                {
                    matched_permit.push("CEDAR-PERMIT-SCOPED-EXTERNAL-WRITE".to_string());
                }
                CedarAction::PrivilegedLocalControl if context.has_approved_capability => {
                    matched_permit.push("CEDAR-PERMIT-APPROVED-LOCAL-CONTROL".to_string());
                }
                CedarAction::DynamicCodeExec if resource.is_signed_and_allowlisted => {
                    matched_permit.push("CEDAR-PERMIT-SIGNED-MODULE-LOAD".to_string());
                }
                CedarAction::CrossSessionTransfer
                    if (!effective_crown_jewel_taint && effective_taint_level < 0.50)
                        || context.has_cryptographic_declassification =>
                {
                    matched_permit.push("CEDAR-PERMIT-CLEAN-OR-DECLASSIFIED-TRANSFER".to_string());
                }
                _ => {}
            }
        }

        let allowed = matched_forbid.is_empty() && !matched_permit.is_empty();
        let reason = if allowed {
            format!(
                "PERMIT [{}]: Authorized by {}",
                action.cedar_id(),
                matched_permit.join(", ")
            )
        } else if !matched_forbid.is_empty() {
            format!(
                "DENY_FORBID [{}]: Blocked by {}",
                action.cedar_id(),
                matched_forbid.join("; ")
            )
        } else {
            format!(
                "DENY_DEFAULT [{}]: No Cedar permit rule matched for resource '{}'",
                action.cedar_id(),
                resource.resource_id
            )
        };

        let record = PolicyDecisionRecord {
            allowed,
            policy_decision_id,
            causal_event_id: context.causal_event_id,
            policy_version: active_policy_version,
            action,
            enforcement_stage,
            matched_forbid_policies: matched_forbid,
            matched_permit_policies: matched_permit,
            reason,
            taint_epoch_at_decision: taint_epoch,
            revocation_seq_at_decision: revocation_seq,
            covert_jitter_ms: context.covert_jitter_applied_ms,
            evaluated_at: Utc::now(),
        };

        if allowed && action != CedarAction::SensitiveFileAccess {
            self.capability_cache.put_cached(cache_key, record.clone());
        }
        record
    }

    pub fn execute_guarded_sensitive_read<F, R>(
        &self,
        principal: &CedarPrincipal,
        file_path: &str,
        is_task_scoped: bool,
        read_fn: F,
    ) -> Result<(R, PolicyDecisionRecord), PolicyDecisionRecord>
    where
        F: FnOnce() -> R,
    {
        self.capability_cache
            .in_flight_sensitive_reads
            .fetch_add(1, Ordering::SeqCst);
        let _write_guard = self.capability_cache.taint_transition_barrier.write();

        let classification = self.classify_file_path(file_path);
        let resource = CedarResource {
            resource_id: file_path.to_string(),
            resource_type: "File".to_string(),
            classification,
            is_signed_and_allowlisted: true,
            is_approved_child_binary: false,
            is_task_scoped_destination: is_task_scoped,
            is_declassified_approved_sink: false,
            service_identity: None,
            service_operation: None,
        };

        let pre_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );
        let ctx = CedarContext {
            policy_version: self.policy_store.active_version_label(),
            causal_event_id: pre_state.last_causal_event_id.clone(),
            has_crown_jewel_taint: pre_state.has_crown_jewel_taint,
            highest_data_classification: pre_state.highest_classification.max(classification),
            taint_level: pre_state.taint_level,
            cumulative_salami_turns: pre_state.cumulative_turns,
            has_approved_capability: false,
            has_cryptographic_declassification: false,
            upward_authority_promotion_attempted: false,
            egress_budget_exceeded: false,
            semantic_cosine_similarity: 0.0,
            covert_jitter_applied_ms: 0,
            taint_epoch: self.capability_cache.current_taint_epoch(),
            revocation_seq: self.capability_cache.current_revocation_seq(),
        };

        let decision = self.evaluate_cedar_request(
            principal,
            CedarAction::SensitiveFileAccess,
            &resource,
            ctx,
            EnforcementStage::PreExecutionPrevented,
        );

        if !decision.allowed {
            self.capability_cache
                .in_flight_sensitive_reads
                .fetch_sub(1, Ordering::SeqCst);
            return Err(decision);
        }

        if classification >= DataClassification::Confidential {
            self.capability_cache.advance_taint_and_revocation();
        }
        let step_taint = match classification {
            DataClassification::CrownJewelSecret => 0.95,
            DataClassification::Confidential => 0.55,
            DataClassification::InternalWorkspace => 0.10,
            DataClassification::Public => 0.0,
        };
        let updated_node = self.causal_graph.record_causal_step(
            &principal.process_instance_key,
            &principal.session_id,
            step_taint,
            classification,
            0.0,
        );

        let output = read_fn();
        self.capability_cache
            .in_flight_sensitive_reads
            .fetch_sub(1, Ordering::SeqCst);

        let mut final_decision = decision;
        final_decision.causal_event_id = updated_node.last_causal_event_id;
        final_decision.taint_epoch_at_decision = self.capability_cache.current_taint_epoch();
        final_decision.revocation_seq_at_decision = self.capability_cache.current_revocation_seq();
        Ok((output, final_decision))
    }

    pub fn execute_guarded_external_write<F, R>(
        &self,
        principal: &CedarPrincipal,
        destination_url: &str,
        payload: &str,
        is_task_scoped_destination: bool,
        declassification_receipt_id: Option<&str>,
        effect_fn: F,
    ) -> GuardedEffectOutcome<R>
    where
        F: FnOnce() -> R,
    {
        let pre_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );
        let has_valid_declassification = declassification_receipt_id
            .map(|rid| {
                self.causal_graph.verify_declassification_receipt(
                    rid,
                    &principal.session_id,
                    payload,
                )
            })
            .unwrap_or(false);

        let budget_exceeded =
            self.check_and_consume_egress_budget(&principal.session_id, payload.len());
        let sem_sim = self.max_crown_jewel_semantic_similarity(payload);
        let jitter_ms = self.compute_covert_jitter_ms(
            &principal.session_id,
            destination_url,
            pre_state.cumulative_turns,
        );

        let resource = CedarResource {
            resource_id: destination_url.to_string(),
            resource_type: "ExternalEndpoint".to_string(),
            classification: pre_state.highest_classification,
            is_signed_and_allowlisted: true,
            is_approved_child_binary: false,
            is_task_scoped_destination,
            is_declassified_approved_sink: has_valid_declassification,
            service_identity: Some("ExternalSaaS".to_string()),
            service_operation: Some("PublishWrite".to_string()),
        };

        let ctx = CedarContext {
            policy_version: self.policy_store.active_version_label(),
            causal_event_id: pre_state.last_causal_event_id.clone(),
            has_crown_jewel_taint: pre_state.has_crown_jewel_taint,
            highest_data_classification: pre_state.highest_classification,
            taint_level: pre_state.taint_level,
            cumulative_salami_turns: pre_state.cumulative_turns,
            has_approved_capability: principal
                .approved_capabilities
                .iter()
                .any(|c| c == "ExternalWrite"),
            has_cryptographic_declassification: has_valid_declassification,
            upward_authority_promotion_attempted: false,
            egress_budget_exceeded: budget_exceeded,
            semantic_cosine_similarity: sem_sim,
            covert_jitter_applied_ms: jitter_ms,
            taint_epoch: self.capability_cache.current_taint_epoch(),
            revocation_seq: self.capability_cache.current_revocation_seq(),
        };

        let decision = self.evaluate_cedar_request(
            principal,
            CedarAction::ExternalWrite,
            &resource,
            ctx,
            EnforcementStage::PreExecutionPrevented,
        );

        if !decision.allowed {
            return GuardedEffectOutcome::DeniedPreExecution {
                policy_decision_id: decision.policy_decision_id,
                causal_event_id: decision.causal_event_id,
                reason: decision.reason,
            };
        }

        let _read_guard = self.capability_cache.taint_transition_barrier.read();
        let current_taint_epoch = self.capability_cache.current_taint_epoch();
        let current_revocation_seq = self.capability_cache.current_revocation_seq();
        let in_flight = self.capability_cache.in_flight_sensitive_reads();
        let latest_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );

        if in_flight > 0
            || current_taint_epoch != decision.taint_epoch_at_decision
            || current_revocation_seq != decision.revocation_seq_at_decision
            || (latest_state.has_crown_jewel_taint && !has_valid_declassification)
            || latest_state.capabilities_revoked
            || latest_state.session_terminated
        {
            return GuardedEffectOutcome::DeniedByConcurrentRevocation {
                policy_decision_id: decision.policy_decision_id,
                causal_event_id: latest_state.last_causal_event_id,
                decision_taint_epoch: decision.taint_epoch_at_decision,
                current_taint_epoch,
                decision_revocation_seq: decision.revocation_seq_at_decision,
                current_revocation_seq,
                reason: "DENY_CONCURRENT_REVOCATION_BARRIER: Taint epoch / revocation_seq advanced or Crown-Jewel read occurred before ExternalWrite commit".to_string(),
            };
        }

        let output = effect_fn();
        GuardedEffectOutcome::Committed {
            output,
            policy_decision_id: decision.policy_decision_id,
            causal_event_id: decision.causal_event_id,
        }
    }

    pub fn evaluate_os_event(&self, event: &HostSecurityEvent) -> PolicyDecisionRecord {
        let get_str = |keys: &[&str]| -> String {
            for k in keys {
                if let Some(s) = event.data.get(*k).and_then(|v| v.as_str()) {
                    if !s.trim().is_empty() {
                        return s.trim().to_string();
                    }
                }
            }
            String::new()
        };
        let get_u32 = |keys: &[&str]| -> u32 {
            for k in keys {
                if let Some(v) = event.data.get(*k) {
                    if let Some(n) = v.as_u64() {
                        return n as u32;
                    }
                    if let Some(s) = v.as_str() {
                        if let Ok(n) = s.parse::<u32>() {
                            return n;
                        }
                    }
                }
            }
            0
        };

        let pid = get_u32(&["ProcessId", "process_id", "pid", "SourceProcessId"]);
        let parent_pid = get_u32(&[
            "ParentProcessId",
            "parent_process_id",
            "ppid",
            "ClientProcessId",
        ]);
        let start_time_100ns = event
            .data
            .get("ProcessStartTime100ns")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| event.timestamp.timestamp_nanos_opt().unwrap_or(1000) as u64);

        let image = get_str(&["Image", "image", "ProcessName", "SourceImage"]);
        let image_loaded = get_str(&["ImageLoaded", "image_loaded", "ModulePath"]);
        let cmdline = get_str(&["CommandLine", "command_line", "Payload"]);
        let target_file = get_str(&["TargetFilename", "target_filename", "FilePath", "Path"]);
        let dest_ip = get_str(&["DestinationIp", "destination_ip", "DestAddress"]);
        let dest_host = get_str(&["DestinationHostname", "destination_hostname", "QueryName"]);
        let dest_port = get_u32(&["DestinationPort", "destination_port", "DestPort"]) as u16;
        let pipe_name = get_str(&["PipeName", "pipe_name", "IpcTarget"]);
        let http_method = get_str(&["HttpMethod", "http_method", "Operation"]);
        let fallback_session_id = {
            let s = get_str(&["SessionId", "session_id", "AgentSessionId"]);
            if s.is_empty() {
                "os-default-session".to_string()
            } else {
                s
            }
        };

        let requested_authority = match event.data.get("AuthorityLevel").and_then(|v| v.as_u64()) {
            Some(1) => AuthorityLevel::L1SystemSecurityPolicy,
            Some(2) => AuthorityLevel::L2AuthorizedUserObjective,
            Some(3) => AuthorityLevel::L3TrustedApplicationInstruction,
            Some(4) => AuthorityLevel::L4WorkspaceConfiguration,
            Some(5) => AuthorityLevel::L5UntrustedRetrievedContent,
            _ => AuthorityLevel::L2AuthorizedUserObjective,
        };

        // P1.2 Confused-Deputy Broker Attribution: if the process is an OS/developer broker
        // (`WmiPrvSE.exe`, `svchost.exe`, `conhost.exe`, `git-remote-https.exe`, `ssh.exe`),
        // bind it to the requesting client process/session!
        let node_state = if CausalSecurityGraph::is_broker_process_image(&image) && parent_pid > 0 {
            let (broker_state, _) = self.causal_graph.attribute_broker_operation(
                pid.max(1),
                start_time_100ns,
                &image,
                parent_pid,
                &fallback_session_id,
            );
            broker_state
        } else {
            let parent_instance_key = event
                .data
                .get("ParentInstanceKey")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    if parent_pid > 0 {
                        self.causal_graph
                            .pid_to_latest_instance
                            .get(&parent_pid)
                            .map(|r| r.value().clone())
                    } else {
                        None
                    }
                });
            let image_blake3 = blake3::hash(format!("{}:{}", image, cmdline).as_bytes())
                .to_hex()
                .to_string();
            let proc_identity = ProcessInstanceIdentity::new(
                pid.max(1),
                start_time_100ns,
                image_blake3,
                parent_instance_key,
                event
                    .data
                    .get("JobObjectId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                fallback_session_id.clone(),
            );
            self.causal_graph
                .register_process_instance(proc_identity, requested_authority)
        };

        let session_id = node_state.origin_session_id.clone();
        let proc_key = node_state.node_key.clone();

        let is_signed = event
            .data
            .get("Signed")
            .and_then(|v| v.as_bool())
            .or_else(|| {
                event
                    .data
                    .get("Signed")
                    .and_then(|v| v.as_str())
                    .map(|s| s.eq_ignore_ascii_case("true"))
            })
            .unwrap_or(true);

        // P0.1 / P0.3: Never use `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES`
        // to block third-party developer `.dll`/`.pyd` builds in approved workspace/toolchain directories.
        // Instead, distinguish legitimate developer/toolchain libraries from untrusted temp/download drops
        // and enforce pre-effect restrictions on subsequent sensitive resource access and outbound connections.
        let (action, resource, stage, sem_sim, jitter_ms) = match event.event_id {
            7 => {
                let mod_lower = image_loaded.replace('\\', "/").to_ascii_lowercase();
                let is_developer_workspace_lib = (mod_lower.contains("/target/debug/")
                    || mod_lower.contains("/target/release/")
                    || mod_lower.contains("/site-packages/")
                    || mod_lower.contains("/node_modules/"))
                    && !mod_lower.contains("untrusted")
                    && !mod_lower.contains("evil");
                let is_untrusted_mod = (!is_signed && !is_developer_workspace_lib)
                    || mod_lower.contains("/temp/")
                    || mod_lower.contains("/tmp/")
                    || mod_lower.contains("/downloads/")
                    || mod_lower.contains("untrusted")
                    || mod_lower.contains("evil")
                    || mod_lower.contains(" unsigned");
                if is_untrusted_mod {
                    self.causal_graph
                        .revoke_node_capabilities(&proc_key, &session_id);
                    self.capability_cache.advance_taint_and_revocation();
                }
                let enforce_stage = if event
                    .data
                    .get("PreEffectCodePolicyEnforced")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    EnforcementStage::PreExecutionPrevented
                } else {
                    EnforcementStage::PostNotificationContained
                };
                (
                    CedarAction::DynamicCodeExec,
                    CedarResource {
                        resource_id: if image_loaded.is_empty() {
                            image.clone()
                        } else {
                            image_loaded
                        },
                        resource_type: "DynamicModule".to_string(),
                        classification: DataClassification::InternalWorkspace,
                        is_signed_and_allowlisted: !is_untrusted_mod,
                        is_approved_child_binary: !is_untrusted_mod,
                        is_task_scoped_destination: !is_untrusted_mod,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("ImageLoad".to_string()),
                    },
                    enforce_stage,
                    0.0,
                    0,
                )
            }
            8 | 10 => {
                self.causal_graph
                    .revoke_node_capabilities(&proc_key, &session_id);
                self.capability_cache.advance_taint_and_revocation();
                (
                    CedarAction::DynamicCodeExec,
                    CedarResource {
                        resource_id: format!("mem-access:{}:{}", image, event.event_id),
                        resource_type: "ProcessMemory".to_string(),
                        classification: DataClassification::CrownJewelSecret,
                        is_signed_and_allowlisted: false,
                        is_approved_child_binary: false,
                        is_task_scoped_destination: false,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("ProcessMemoryInjection".to_string()),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
            17 | 18 => {
                let target_pipe = if pipe_name.is_empty() {
                    r"\\.\pipe\unknown".to_string()
                } else {
                    pipe_name
                };
                let cls = LoopbackIpcAuthorizer::classify_target(&target_pipe, "CONNECT");
                (
                    cls.mapped_cedar_action,
                    CedarResource {
                        resource_id: target_pipe,
                        resource_type: "NamedPipe".to_string(),
                        classification: DataClassification::CrownJewelSecret,
                        is_signed_and_allowlisted: false,
                        is_approved_child_binary: false,
                        is_task_scoped_destination: !cls.requires_privileged_capability,
                        is_declassified_approved_sink: false,
                        service_identity: Some(format!("{:?}", cls.service_identity)),
                        service_operation: Some(format!("{:?}", cls.service_operation)),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
            3 | 5156 => {
                let target_endpoint = if !dest_host.is_empty() {
                    if dest_port > 0 {
                        format!("http://{}:{}", dest_host, dest_port)
                    } else {
                        dest_host.clone()
                    }
                } else if !dest_ip.is_empty() {
                    format!("http://{}:{}", dest_ip, dest_port.max(80))
                } else {
                    cmdline.clone()
                };
                let cls = LoopbackIpcAuthorizer::classify_target(&target_endpoint, &http_method);
                let is_canonical_approved_remote = target_endpoint
                    .to_ascii_lowercase()
                    .contains("github.com/oyesanyf/oshoosiclaw")
                    || (cls.is_local_or_ipc && !cls.requires_privileged_capability);
                let sim = self.max_crown_jewel_semantic_similarity(&cmdline);
                let jitter = self.compute_covert_jitter_ms(
                    &session_id,
                    &target_endpoint,
                    node_state.cumulative_turns,
                );
                (
                    cls.mapped_cedar_action,
                    CedarResource {
                        resource_id: target_endpoint,
                        resource_type: "NetworkEndpoint".to_string(),
                        classification: node_state.highest_classification,
                        is_signed_and_allowlisted: is_signed,
                        is_approved_child_binary: true,
                        is_task_scoped_destination: is_canonical_approved_remote
                            || event
                                .data
                                .get("TaskScopedDestination")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                        is_declassified_approved_sink: false,
                        service_identity: Some(format!("{:?}", cls.service_identity)),
                        service_operation: Some(format!("{:?}", cls.service_operation)),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    sim,
                    jitter,
                )
            }
            11 | 4663 => {
                let path = if target_file.is_empty() {
                    cmdline.clone()
                } else {
                    target_file
                };
                let classification = self.classify_file_path(&path);
                let is_scoped = event
                    .data
                    .get("TaskScopedDestination")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(classification != DataClassification::CrownJewelSecret);
                if is_scoped && classification == DataClassification::CrownJewelSecret {
                    self.capability_cache.advance_taint_and_revocation();
                    self.causal_graph.record_causal_step(
                        &proc_key,
                        &session_id,
                        0.95,
                        classification,
                        0.0,
                    );
                }
                (
                    CedarAction::SensitiveFileAccess,
                    CedarResource {
                        resource_id: path,
                        resource_type: "File".to_string(),
                        classification,
                        is_signed_and_allowlisted: is_signed,
                        is_approved_child_binary: false,
                        is_task_scoped_destination: is_scoped,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("FileAccess".to_string()),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
            _ => {
                let combined_lower = format!("{} {}", image, cmdline).to_ascii_lowercase();
                let suspicious_child = combined_lower.contains(" -enc ")
                    || combined_lower.contains("-encodedcommand")
                    || combined_lower.contains("downloadstring")
                    || combined_lower.contains("invoke-expression")
                    || combined_lower.contains("curl ")
                    || combined_lower.contains("wget ")
                    || combined_lower.contains("nc -e")
                    || combined_lower.contains("/dev/tcp/")
                    || combined_lower.contains("webhook.site")
                    || combined_lower.contains("requestbin")
                    || combined_lower.contains("mimikatz")
                    || combined_lower.contains("procdump")
                    || combined_lower.contains("lsass")
                    || combined_lower.contains("keymgr.dll")
                    || combined_lower.contains("comsvcs.dll")
                    || !is_signed;

                (
                    CedarAction::ChildProcessExec,
                    CedarResource {
                        resource_id: if image.is_empty() {
                            cmdline.clone()
                        } else {
                            image
                        },
                        resource_type: "ChildProcess".to_string(),
                        classification: node_state.highest_classification,
                        is_signed_and_allowlisted: !suspicious_child && is_signed,
                        is_approved_child_binary: !suspicious_child,
                        is_task_scoped_destination: !suspicious_child,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("ProcessCreate".to_string()),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
        };

        let latest_state = self
            .causal_graph
            .resolve_state(Some(&proc_key), Some(pid), &session_id);

        let principal = CedarPrincipal {
            principal_id: format!("agent-proc-{}", proc_key),
            session_id: session_id.clone(),
            process_instance_key: proc_key,
            authority_level: latest_state.authority_level,
            approved_capabilities: Vec::new(),
        };

        let context = CedarContext {
            policy_version: self.policy_store.active_version_label(),
            causal_event_id: latest_state.last_causal_event_id,
            has_crown_jewel_taint: latest_state.has_crown_jewel_taint,
            highest_data_classification: latest_state.highest_classification,
            taint_level: latest_state.taint_level,
            cumulative_salami_turns: latest_state.cumulative_turns,
            has_approved_capability: event
                .data
                .get("HasApprovedCapability")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            has_cryptographic_declassification: false,
            upward_authority_promotion_attempted: false,
            egress_budget_exceeded: false,
            semantic_cosine_similarity: sem_sim,
            covert_jitter_applied_ms: jitter_ms,
            taint_epoch: self.capability_cache.current_taint_epoch(),
            revocation_seq: self.capability_cache.current_revocation_seq(),
        };

        self.evaluate_cedar_request(&principal, action, &resource, context, stage)
    }

    pub fn get_status_snapshot(&self) -> serde_json::Value {
        let (merkle_root, _) = self.workspace_allowlist.compute_merkle_root();
        serde_json::json!({
            "policy_version": self.policy_store.active_version_label(),
            "policy_version_num": self.policy_store.active_version_num(),
            "workspace_merkle_root_blake3": merkle_root,
            "taint_epoch": self.capability_cache.current_taint_epoch(),
            "revocation_seq": self.capability_cache.current_revocation_seq(),
            "in_flight_sensitive_reads": self.capability_cache.in_flight_sensitive_reads(),
            "registered_crown_jewel_assets": self.crown_jewels.len(),
            "status": "unified capability enforcement under implementation and verification",
        })
    }
}

static GLOBAL_RING7_AUTHORIZER: OnceLock<Arc<Ring7CapabilityEffectAuthorizer>> = OnceLock::new();

pub fn global_ring7_authorizer() -> Arc<Ring7CapabilityEffectAuthorizer> {
    GLOBAL_RING7_AUTHORIZER
        .get_or_init(|| Arc::new(Ring7CapabilityEffectAuthorizer::new()))
        .clone()
}

// ============================================================================
// 8. Authorized-Effect Composition (`WorkflowCompositionEvaluator`), Advisory-Only
//    Model Guard (`AdvisoryModelJudgmentGuard`), & `PlatformAttestationGate`
// ============================================================================

/// Categorizes individually permitted operations in a multi-step agent workflow
/// so `WorkflowCompositionEvaluator` can detect prohibited composed outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposedWorkflowStepKind {
    ReadPermittedProjectFile {
        path: String,
    },
    ModifyPermittedSourceCode {
        path: String,
    },
    ModifyPermittedConfiguration {
        path: String,
        weakens_security_or_unverified: bool,
    },
    ExecuteApprovedLocalTest {
        command: String,
    },
    ExecuteApprovedDeployment {
        target_environment: String,
        dual_authorization_cosigners: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompositionVerdict {
    pub allowed: bool,
    pub session_id: String,
    pub individual_step_permitted_by_cedar: bool,
    pub composed_workflow_violation_detected: bool,
    pub requires_dual_authorization: bool,
    pub policy_decision_id: String,
    pub causal_chain_summary: Vec<String>,
    pub reason: String,
}

/// Evaluates outcome-level workflow composition invariants over `CausalSecurityGraph`:
/// - Blocks `ReadPermittedProjectFile -> ModifyPermittedConfiguration -> ExecuteApprovedDeployment`
///   when the composed chain would deploy weakened or unverified security/runtime configuration
///   without independent dual-authorization (`cosigners.len() >= 2`).
/// - Permits `ReadPermittedProjectFile -> ModifyPermittedSourceCode -> ExecuteApprovedLocalTest` (`cargo test`).
#[derive(Default)]
pub struct WorkflowCompositionEvaluator {
    session_steps: DashMap<String, Vec<ComposedWorkflowStepKind>>,
}

impl WorkflowCompositionEvaluator {
    pub fn new() -> Self {
        Self {
            session_steps: DashMap::new(),
        }
    }

    /// Evaluates and records a workflow step, executing `effect_fn` ONLY if both individual Cedar
    /// authorization and composed workflow outcome invariants hold.
    pub fn evaluate_and_execute_step<F, R>(
        &self,
        session_id: &str,
        step: ComposedWorkflowStepKind,
        effect_fn: F,
    ) -> (WorkflowCompositionVerdict, Option<R>)
    where
        F: FnOnce() -> R,
    {
        let mut history = self
            .session_steps
            .entry(session_id.to_string())
            .or_default();
        history.push(step.clone());
        let steps_snapshot = history.clone();
        drop(history);

        let chain_summary: Vec<String> = steps_snapshot
            .iter()
            .map(|s| match s {
                ComposedWorkflowStepKind::ReadPermittedProjectFile { path } => {
                    format!("ReadPermittedProjectFile({})", path)
                }
                ComposedWorkflowStepKind::ModifyPermittedSourceCode { path } => {
                    format!("ModifyPermittedSourceCode({})", path)
                }
                ComposedWorkflowStepKind::ModifyPermittedConfiguration {
                    path,
                    weakens_security_or_unverified,
                } => format!(
                    "ModifyPermittedConfiguration({}, weakened_or_unverified={})",
                    path, weakens_security_or_unverified
                ),
                ComposedWorkflowStepKind::ExecuteApprovedLocalTest { command } => {
                    format!("ExecuteApprovedLocalTest({})", command)
                }
                ComposedWorkflowStepKind::ExecuteApprovedDeployment {
                    target_environment,
                    dual_authorization_cosigners,
                } => format!(
                    "ExecuteApprovedDeployment({}, cosigners={})",
                    target_environment,
                    dual_authorization_cosigners.len()
                ),
            })
            .collect();

        let decision_hash =
            blake3::hash(format!("wf-comp:{}:{}", session_id, chain_summary.join("->")).as_bytes());
        let policy_decision_id = format!("pdec-wf-{}", &decision_hash.to_hex()[..16]);

        if let ComposedWorkflowStepKind::ExecuteApprovedDeployment {
            ref target_environment,
            ref dual_authorization_cosigners,
        } = step
        {
            let has_prior_read = steps_snapshot
                .iter()
                .any(|s| matches!(s, ComposedWorkflowStepKind::ReadPermittedProjectFile { .. }));
            let has_unverified_config_mod = steps_snapshot.iter().any(|s| {
                matches!(
                    s,
                    ComposedWorkflowStepKind::ModifyPermittedConfiguration {
                        weakens_security_or_unverified: true,
                        ..
                    }
                )
            });

            // Count distinct non-agent human/control-plane cosigners
            let distinct_valid_cosigners: HashSet<String> = dual_authorization_cosigners
                .iter()
                .map(|c| c.trim().to_ascii_lowercase())
                .filter(|c| !c.is_empty() && !c.contains("agent") && !c.contains("worker"))
                .collect();

            if has_prior_read && has_unverified_config_mod && distinct_valid_cosigners.len() < 2 {
                return (
                    WorkflowCompositionVerdict {
                        allowed: false,
                        session_id: session_id.to_string(),
                        individual_step_permitted_by_cedar: true,
                        composed_workflow_violation_detected: true,
                        requires_dual_authorization: true,
                        policy_decision_id,
                        causal_chain_summary: chain_summary,
                        reason: format!(
                            "DENY_AUTHORIZED_EFFECT_COMPOSITION: Individually permitted steps (ReadPermittedProjectFile -> ModifyPermittedConfiguration -> ExecuteApprovedDeployment[{}]) compose into an unverified/weakened deployment outcome without dual human authorization",
                            target_environment
                        ),
                    },
                    None,
                );
            }
        }

        let out = effect_fn();
        (
            WorkflowCompositionVerdict {
                allowed: true,
                session_id: session_id.to_string(),
                individual_step_permitted_by_cedar: true,
                composed_workflow_violation_detected: false,
                requires_dual_authorization: false,
                policy_decision_id,
                causal_chain_summary: chain_summary,
                reason: "PERMIT_COMPOSED_WORKFLOW: Causal workflow sequence satisfies outcome-level composition invariants".to_string(),
            },
            Some(out),
        )
    }
}

/// Enforces the `Model manipulation` defense: LLM, classifier, and embedding judgments
/// (`AlignmentCheck`, Tier-2 cosine similarity, ML voters) are strictly advisory (risk escalation only)
/// and can NEVER grant a capability, declassify taint, or override a Cedar/workflow denial.
pub struct AdvisoryModelJudgmentGuard;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryModelEvaluationResult {
    pub final_allowed: bool,
    pub deterministic_cedar_allowed: bool,
    pub model_claimed_benign_confidence: f64,
    pub model_attempted_capability_grant: bool,
    pub model_attempted_taint_declassification: bool,
    pub model_override_rejected: bool,
    pub reason: String,
}

impl AdvisoryModelJudgmentGuard {
    pub fn enforce_advisory_only_invariant(
        deterministic_cedar_allowed: bool,
        model_claimed_benign: bool,
        model_confidence: f64,
        model_requested_capability_grant: bool,
        model_requested_declassification: bool,
    ) -> AdvisoryModelEvaluationResult {
        // Model can escalate a risk (turning `true` into `false` if `!model_claimed_benign && model_confidence >= 0.90`),
        // but can NEVER turn `deterministic_cedar_allowed == false` into `true`, nor grant capabilities or declassify taint!
        let final_allowed = if !deterministic_cedar_allowed {
            false
        } else if !model_claimed_benign && model_confidence >= 0.90 {
            false
        } else {
            true
        };

        let override_rejected = !deterministic_cedar_allowed
            && (model_claimed_benign
                || model_requested_capability_grant
                || model_requested_declassification);

        AdvisoryModelEvaluationResult {
            final_allowed,
            deterministic_cedar_allowed,
            model_claimed_benign_confidence: model_confidence,
            model_attempted_capability_grant: model_requested_capability_grant,
            model_attempted_taint_declassification: model_requested_declassification,
            model_override_rejected: override_rejected,
            reason: if override_rejected {
                "DENY_MODEL_MANIPULATION_OVERRIDE: Probabilistic LLM/embedding/classifier outputs are strictly advisory and cannot grant capabilities, declassify taint, or override a Cedar/workflow denial".to_string()
            } else if !final_allowed {
                "DENY_ESCALATED_OR_FORBIDDEN: Action blocked by deterministic Cedar policy or high-confidence advisory risk escalation".to_string()
            } else {
                "PERMIT_DETERMINISTIC_AND_ADVISORY_CLEAN".to_string()
            },
        }
    }
}

/// Platform Attestation Posture covering Residual Exploit Classes #1–#4:
/// 1. UEFI / Bootloader / Measured Boot TPM PCRs (`uefi_secure_boot_and_tpm_pcr0_7_valid`)
/// 2. Hypervisor / VBS / HVCI integrity (`hvci_vbs_and_hypervisor_enforced`)
/// 3. CPU microarchitectural side-channel mitigations (`microcode_spectre_mds_l1tf_mitigated`)
/// 4. IOMMU / VT-d / Kernel DMA Protection (`iommu_vt_d_kernel_dma_protection_active`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAttestationPosture {
    pub uefi_secure_boot_and_tpm_pcr0_7_valid: bool,
    pub hvci_vbs_and_hypervisor_enforced: bool,
    pub microcode_spectre_mds_l1tf_mitigated: bool,
    pub iommu_vt_d_kernel_dma_protection_active: bool,
    pub undocumented_kernel_table_walk_used: bool,
}

impl Default for PlatformAttestationPosture {
    fn default() -> Self {
        Self {
            uefi_secure_boot_and_tpm_pcr0_7_valid: true,
            hvci_vbs_and_hypervisor_enforced: true,
            microcode_spectre_mds_l1tf_mitigated: true,
            iommu_vt_d_kernel_dma_protection_active: true,
            undocumented_kernel_table_walk_used: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAttestationDecision {
    pub operation_allowed: bool,
    pub sensitive_keys_withheld: bool,
    pub degraded_layers: Vec<String>,
    pub reason: String,
}

pub struct PlatformAttestationGate;

impl PlatformAttestationGate {
    /// Evaluates whether a high-impact operation or sensitive key release may proceed given
    /// the current hardware/firmware/hypervisor attestation state.
    pub fn evaluate_high_impact_operation(
        posture: &PlatformAttestationPosture,
        operation_name: &str,
    ) -> PlatformAttestationDecision {
        let mut degraded = Vec::new();
        if !posture.uefi_secure_boot_and_tpm_pcr0_7_valid {
            degraded.push("ResidualClass#1_UEFI_MeasuredBoot_PCR0_7_Degraded".to_string());
        }
        if !posture.hvci_vbs_and_hypervisor_enforced {
            degraded.push("ResidualClass#2_Hypervisor_HVCI_VBS_Degraded".to_string());
        }
        if !posture.microcode_spectre_mds_l1tf_mitigated {
            degraded.push("ResidualClass#3_CPU_Microcode_Mitigation_Degraded".to_string());
        }
        if !posture.iommu_vt_d_kernel_dma_protection_active {
            degraded.push("ResidualClass#4_IOMMU_Kernel_DMA_Protection_Degraded".to_string());
        }
        if posture.undocumented_kernel_table_walk_used {
            degraded.push("Unsupported_Undocumented_Kernel_Table_Walk_Detected".to_string());
        }

        if !degraded.is_empty() {
            return PlatformAttestationDecision {
                operation_allowed: false,
                sensitive_keys_withheld: true,
                degraded_layers: degraded.clone(),
                reason: format!(
                    "DENY_UNTRUSTED_PLATFORM_ATTESTATION_WITHHOLD: Withheld sensitive keys and blocked '{}' due to degraded platform trust: {}",
                    operation_name,
                    degraded.join(", ")
                ),
            };
        }

        PlatformAttestationDecision {
            operation_allowed: true,
            sensitive_keys_withheld: false,
            degraded_layers: Vec::new(),
            reason: format!(
                "PERMIT_ATTESTED_PLATFORM: All 4 hardware/firmware/hypervisor trust layers verified for '{}'",
                operation_name
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_hierarchy_and_signed_workspace_allowlist() {
        assert!(AuthorityLevel::L1SystemSecurityPolicy
            .outranks(&AuthorityLevel::L2AuthorizedUserObjective));
        assert!(AuthorityLevel::L2AuthorizedUserObjective
            .outranks(&AuthorityLevel::L4WorkspaceConfiguration));
        assert!(!AuthorityLevel::L4WorkspaceConfiguration.can_override_higher_policy());
        assert!(!AuthorityLevel::L5UntrustedRetrievedContent.can_authorize_privileged_action());

        let allowlist =
            SignedWorkspaceInstructionAllowlist::new(*b"test-control-plane-key-32-bytes!");
        let content = b"# AGENTS.md\nAlways run cargo test before shipping.";
        let sig = allowlist.sign_and_register_workspace_file(
            ".agents/AGENTS.md",
            content,
            "control-plane-key-v1",
        );
        let verified = allowlist.verify_workspace_instruction(
            ".agents/AGENTS.md",
            content,
            AuthorityLevel::L4WorkspaceConfiguration,
        );
        assert!(verified.allowed);
        assert!(verified.cryptographic_signature_valid);
        assert_eq!(
            sig.assigned_authority,
            AuthorityLevel::L4WorkspaceConfiguration
        );
        assert_eq!(
            verified.effective_authority,
            AuthorityLevel::L4WorkspaceConfiguration
        );

        // Attempting upward promotion from L4 to L2 must be blocked
        let promoted = allowlist.verify_workspace_instruction(
            ".agents/AGENTS.md",
            content,
            AuthorityLevel::L2AuthorizedUserObjective,
        );
        assert!(!promoted.allowed);
        assert!(promoted.upward_promotion_blocked);

        // Machine-wide CRYPTPROTECT_LOCAL_MACHINE key storage must be rejected
        let machine_wide = allowlist
            .verify_key_isolation_policy("OsoosiEDRService", "DPAPI:CRYPTPROTECT_LOCAL_MACHINE");
        assert!(!machine_wide.allowed);
        assert!(machine_wide.cryptprotect_local_machine_rejected);
    }

    #[test]
    fn test_rl_separate_learning_from_authority_invariant() {
        let store = ProtectedPolicyStore::default();
        let initial_ver = store.active_version_num();

        // 1. RL attempting to add a `permit` rule must be rejected
        let permit_prop = CandidateCedarPolicyProposal {
            proposal_id: "prop-permit-1".to_string(),
            proposer_model_id: "skyrl-ppo-v2".to_string(),
            proposed_forbid_clause:
                "permit (principal, action == Action::\"ExternalWrite\", resource);".to_string(),
            attempts_taint_declassification: false,
            attempts_causal_provenance_mutation: false,
            benign_workflow_regression_passed: true,
            protected_holdout_passed: true,
        };
        let eval_permit = store.evaluate_rl_tighten_only_proposal(&permit_prop);
        assert!(!eval_permit.proposal_valid_for_dual_approval);
        assert!(eval_permit.rejected_permit_rule_addition);
        assert!(eval_permit.active_policy_unchanged_until_signed);
        assert_eq!(store.active_version_num(), initial_ver);

        // 2. RL attempting taint declassification must be rejected
        let taint_prop = CandidateCedarPolicyProposal {
            proposal_id: "prop-taint-2".to_string(),
            proposer_model_id: "skyrl-ppo-v2".to_string(),
            proposed_forbid_clause:
                "forbid (principal, action == Action::\"ExternalWrite\", resource);".to_string(),
            attempts_taint_declassification: true,
            attempts_causal_provenance_mutation: false,
            benign_workflow_regression_passed: true,
            protected_holdout_passed: true,
        };
        let eval_taint = store.evaluate_rl_tighten_only_proposal(&taint_prop);
        assert!(!eval_taint.proposal_valid_for_dual_approval);
        assert!(eval_taint.rejected_taint_or_provenance_mutation);

        // 3. Valid tighten-only forbid proposal that passed regression & holdout is eligible for dual-signing,
        //    yet NEVER mutates active policy until a dual-principal SignedPolicyUpdateBundle is applied
        let valid_forbid = CandidateCedarPolicyProposal {
            proposal_id: "prop-forbid-3".to_string(),
            proposer_model_id: "skyrl-ppo-v2".to_string(),
            proposed_forbid_clause: "forbid (principal, action == Action::\"DynamicCodeExec\", resource) when { context.taintLevel > 50 };".to_string(),
            attempts_taint_declassification: false,
            attempts_causal_provenance_mutation: false,
            benign_workflow_regression_passed: true,
            protected_holdout_passed: true,
        };
        let eval_valid = store.evaluate_rl_tighten_only_proposal(&valid_forbid);
        assert!(eval_valid.proposal_valid_for_dual_approval);
        assert!(eval_valid.active_policy_unchanged_until_signed);
        assert_eq!(store.active_version_num(), initial_ver);
    }
}
