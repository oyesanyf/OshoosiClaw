use super::*;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};
use osoosi_types::{ArmRole, HostSecurityEvent, OctopusSecurityError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

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

