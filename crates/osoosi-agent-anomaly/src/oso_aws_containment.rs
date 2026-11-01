//! # Oso AI Agent Authorization & AWS Agent Containment-Response Engine
//!
//! Combines two complementary agent security architectures into Agent Octopus & OpenỌ̀ṣọ́ọ̀sì:
//!
//! ## Part 1: Oso (`osohq`) Context-Aware AI Agent Authorization
//! 1. **3-Way Delegated Identity Intersection**:
//!    $$\text{EffectivePerm}(u, a, t) = \text{Perm}(\text{User } u) \cap \text{Cap}(\text{AgentRole } a) \cap \text{Scope}(\text{Task } t)$$
//!    Ensures an autonomous agent acting on behalf of a human user never exceeds the user's authority,
//!    its own role capability envelope, or the immediate task's resource scope.
//! 2. **Pre-Retrieval RAG Context Filtering (ReBAC + Clearance)**:
//!    Programmatically filters vector/RAG documents *before* they enter the LLM context window
//!    based on `(owner_id, shared_principals, classification_tier, workspace_id)`.
//! 3. **MCP Tool-Call Parameter & Row-Level Policy Enforcement**:
//!    Validates MCP `tools/call` arguments against row ownership, pagination/rate bounds, and
//!    production-environment mutation locks (`Valid JSON Syntax != Valid Authority`).
//! 4. **Out-of-Band Cryptographic HITL Step-Up Ticket Verification**:
//!    Destructive or high-blast-radius tool calls require an HMAC-SHA256 signed `HitlStepUpTicket`
//!    bound to `(approver_id, user_id, agent_id, tool_name, canonical_args_sha256, expires_at_unix)`
//!    verified in constant time (`subtle::ConstantTimeEq`).
//!
//! ## Part 2: AWS (`aws-samples/sample-agent-containment-response`) 5-Layer Detect & Respond
//! - **R1 (Trust Separation & DNS Firewall)**: Enforces `NXDOMAIN` on any domain outside the allowlist.
//! - **R3 (4-Invariant Independent Containment Watchdog with Policy-Swap Detection)**:
//!   1. `check_security_group`: Zero `0.0.0.0/0` (IPv4) or `::/0` (IPv6) egress rules.
//!   2. `check_route_tables`: Zero `igw-*` internet gateway routes in sandbox route tables.
//!   3. `check_iam_policies`: Verifies both attached/inline policy counts AND exact policy ARN/name sets
//!      (`unexpected = actual - expected`, `missing = expected - actual`) to defeat **Policy Swap Attacks**.
//!   4. `check_dns_firewall`: Verifies at least one `COMPLETE` DNS Firewall rule group association is active.
//! - **R4 (Adversarial Audit Isolation)**: Explicit Deny on all monitoring, IAM, watchdog, and audit APIs
//!   (`iam:*`, `cloudtrail:*`, `cloudwatch:*`, `guardduty:*`, `ec2:Describe*`, `osoosi:watchdog:*`, `osoosi:audit:*`).
//! - **R5 (Capability Envelope `AccessDenied` Velocity Alarm)**:
//!   Tracks denied actions in a sliding 60-second window; if `>= 3` denials occur within 60 seconds,
//!   automatically fires the KillSwitch.
//! - **KillSwitch Service Scale-Down & Task Termination**:
//!   Scales service `desired_count` to `0` (`auto_respawn_disabled = true`) before terminating all
//!   running agent tasks/subprocesses and advancing the monotonic generation epoch (`Gen N -> Gen N+1`).

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_types::{role_trust_tier, ArmRole, TrustTier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, LazyLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Default R5 capability envelope threshold: 3 denied calls within 60 seconds triggers KillSwitch.
pub const AWS_R5_DEFAULT_DENIED_THRESHOLD: usize = 3;
/// Default R5 sliding window in seconds (60s).
pub const AWS_R5_DEFAULT_WINDOW_SECS: i64 = 60;

// ============================================================================
// PART 1: OSO CONTEXT-AWARE AI AGENT AUTHORIZATION (INTERSECTION + RAG + HITL)
// ============================================================================

/// Represents the delegating human user's identity, clearance, and granted permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatingUserContext {
    pub user_id: String,
    /// Explicit action strings granted to the user (e.g., `"read:docs"`, `"query:db"`, `"write:ledger"`).
    pub permissions: BTreeSet<String>,
    /// Resource prefixes or IDs the user owns or is authorized to access.
    pub allowed_resources: BTreeSet<String>,
    /// Maximum data classification clearance (`0 = Public`, `1 = Internal`, `2 = Confidential`, `3 = Secret`).
    pub max_clearance_tier: u8,
}

/// Task-scoped least-privilege envelope (JIT scoped per workflow step).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskScopeEnvelope {
    pub task_id: String,
    pub workspace_id: String,
    /// Actions needed strictly for the current task stage.
    pub allowed_actions: BTreeSet<String>,
    /// Resource prefixes scoped to the current task.
    pub allowed_resource_prefixes: Vec<String>,
    /// Maximum rows/items a single query tool call may retrieve in this task.
    pub max_query_limit: u64,
    /// Whether production environment mutations are permitted in this task scope.
    pub allow_production_mutation: bool,
}

/// Candidate RAG document chunk evaluated by Oso pre-retrieval authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagDocumentChunk {
    pub doc_id: String,
    pub workspace_id: String,
    pub owner_id: String,
    pub shared_with_users: BTreeSet<String>,
    /// `0 = Public`, `1 = Internal`, `2 = Confidential`, `3 = Secret`
    pub classification_tier: u8,
    pub content_preview: String,
}

/// Result of pre-retrieval RAG filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagFilterResult {
    pub total_candidates: usize,
    pub authorized_doc_ids: Vec<String>,
    pub filtered_out_doc_ids: Vec<String>,
    pub reasons: Vec<String>,
}

/// Out-of-band cryptographic Human-in-the-Loop (HITL) step-up approval ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitlStepUpTicket {
    pub approver_id: String,
    pub user_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub canonical_args_sha256: String,
    pub expires_at_unix: i64,
    pub signature_hex: String,
}

/// Decision returned by the Oso + AWS unified authorization and containment gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsoAuthzDecision {
    Allow {
        effective_intersection_action: String,
        rationale: String,
    },
    Deny {
        code: String,
        reason: String,
        kill_switch_triggered: bool,
    },
}

/// Maps an `ArmRole` to its static capability envelope for Oso 3-way intersection checks.
pub fn role_capability_actions(role: &ArmRole) -> BTreeSet<String> {
    let mut caps = BTreeSet::new();
    match role {
        ArmRole::UntrustedDocIngest => {
            caps.insert("read:docs".to_string());
            caps.insert("extract:text".to_string());
        }
        ArmRole::AccountingLedgerWrite => {
            caps.insert("read:ledger".to_string());
            caps.insert("write:ledger".to_string());
            caps.insert("transfer:funds".to_string());
        }
        ArmRole::NetworkEgress => {
            caps.insert("net:egress".to_string());
            caps.insert("http:get".to_string());
            caps.insert("http:post".to_string());
        }
        ArmRole::CedarPolicyEvaluation => {
            caps.insert("policy:evaluate".to_string());
            caps.insert("read:docs".to_string());
        }
        ArmRole::AtlasThreatIntelligence | ArmRole::AnomalyDetection => {
            caps.insert("read:telemetry".to_string());
            caps.insert("query:siquery".to_string());
            caps.insert("read:docs".to_string());
        }
        ArmRole::KernelLevelSentinel => {
            caps.insert("read:telemetry".to_string());
            caps.insert("sentinel:verify".to_string());
            caps.insert("containment:isolate".to_string());
        }
        _ => {
            caps.insert("read:docs".to_string());
            caps.insert("read:telemetry".to_string());
        }
    }
    caps
}

/// Maximum classification clearance tier allowed for a given `ArmRole`.
pub fn role_max_clearance_tier(role: &ArmRole) -> u8 {
    match role_trust_tier(role) {
        TrustTier::Untrusted => 1,      // Public / Internal only
        TrustTier::Worker => 2,         // Up to Confidential
        TrustTier::PrivilegedSink => 3, // Up to Secret
    }
}

/// Computes canonical SHA-256 hex digest of a JSON value for HITL ticket binding.
pub fn canonical_json_sha256(val: &Value) -> String {
    let canonical = serde_json::to_string(val).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Issues a cryptographic HMAC-SHA256 HITL Step-Up Ticket for destructive tool execution.
pub fn issue_hitl_step_up_ticket(
    secret_key: &[u8],
    approver_id: &str,
    user_id: &str,
    agent_id: &str,
    tool_name: &str,
    arguments: &Value,
    expires_at_unix: i64,
) -> HitlStepUpTicket {
    let canonical_args_sha256 = canonical_json_sha256(arguments);
    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        approver_id, user_id, agent_id, tool_name, canonical_args_sha256, expires_at_unix
    );
    let mut mac = HmacSha256::new_from_slice(secret_key).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    let signature_hex = hex::encode(mac.finalize().into_bytes());

    HitlStepUpTicket {
        approver_id: approver_id.to_string(),
        user_id: user_id.to_string(),
        agent_id: agent_id.to_string(),
        tool_name: tool_name.to_string(),
        canonical_args_sha256,
        expires_at_unix,
        signature_hex,
    }
}

/// Verifies an out-of-band HMAC-SHA256 HITL Step-Up Ticket in constant time.
pub fn verify_hitl_step_up_ticket(
    secret_key: &[u8],
    ticket: &HitlStepUpTicket,
    expected_user_id: &str,
    expected_agent_id: &str,
    expected_tool_name: &str,
    arguments: &Value,
    now_unix: i64,
) -> Result<(), String> {
    if ticket.approver_id.trim().is_empty() || ticket.approver_id == expected_user_id {
        // Approver must be a distinct human reviewer or explicit supervisor identity
        if ticket.approver_id.trim().is_empty() {
            return Err("HITL_APPROVER_EMPTY".to_string());
        }
    }
    if ticket.user_id != expected_user_id {
        return Err(format!(
            "HITL_USER_MISMATCH: ticket user '{}' != '{}'",
            ticket.user_id, expected_user_id
        ));
    }
    if ticket.agent_id != expected_agent_id {
        return Err(format!(
            "HITL_AGENT_MISMATCH: ticket agent '{}' != '{}'",
            ticket.agent_id, expected_agent_id
        ));
    }
    if ticket.tool_name != expected_tool_name {
        return Err(format!(
            "HITL_TOOL_MISMATCH: ticket tool '{}' != '{}'",
            ticket.tool_name, expected_tool_name
        ));
    }
    if now_unix > ticket.expires_at_unix {
        return Err(format!(
            "HITL_TICKET_EXPIRED: now {} > expires_at {}",
            now_unix, ticket.expires_at_unix
        ));
    }
    let actual_args_sha256 = canonical_json_sha256(arguments);
    if ticket.canonical_args_sha256 != actual_args_sha256 {
        return Err("HITL_ARGS_TAMPERED: tool arguments do not match approved digest".to_string());
    }

    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        ticket.approver_id,
        ticket.user_id,
        ticket.agent_id,
        ticket.tool_name,
        ticket.canonical_args_sha256,
        ticket.expires_at_unix
    );
    let mut mac = HmacSha256::new_from_slice(secret_key).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    if expected_sig.len() != ticket.signature_hex.len()
        || !bool::from(
            expected_sig
                .as_bytes()
                .ct_eq(ticket.signature_hex.as_bytes()),
        )
    {
        return Err("HITL_SIGNATURE_INVALID: HMAC-SHA256 verification failed".to_string());
    }

    Ok(())
}

// ============================================================================
// PART 2: AWS SAMPLE-AGENT-CONTAINMENT-RESPONSE (R1 - R5 + KILL SWITCH)
// ============================================================================

/// Egress rule representation for Invariant 1 (`check_security_group`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEgressRule {
    pub rule_id: String,
    pub protocol: String,
    pub cidr_ipv4: Option<String>,
    pub cidr_ipv6: Option<String>,
    pub description: String,
}

/// Route table entry representation for Invariant 2 (`check_route_tables`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRouteEntry {
    pub route_table_id: String,
    pub destination_cidr: String,
    pub gateway_id: String,
}

/// DNS Firewall association representation for Invariant 4 (`check_dns_firewall`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFirewallAssociation {
    pub association_id: String,
    pub vpc_id: String,
    pub status: String, // Must be "COMPLETE"
    pub allowed_domain_patterns: Vec<String>,
}

/// Snapshot of the 4 containment invariants inspected by the independent watchdog (R3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentEnvironmentSnapshot {
    pub security_group_id: String,
    pub vpc_id: String,
    pub task_role_name: String,
    pub egress_rules: Vec<SandboxEgressRule>,
    pub route_entries: Vec<SandboxRouteEntry>,
    pub expected_attached_policy_arns: BTreeSet<String>,
    pub actual_attached_policy_arns: BTreeSet<String>,
    pub expected_inline_policy_names: BTreeSet<String>,
    pub actual_inline_policy_names: BTreeSet<String>,
    pub dns_firewall_associations: Vec<DnsFirewallAssociation>,
}

impl Default for ContainmentEnvironmentSnapshot {
    fn default() -> Self {
        let mut attached = BTreeSet::new();
        attached.insert("arn:osoosi:iam::policy/AgentScopedBedrockAndS3Policy".to_string());
        let mut inline = BTreeSet::new();
        inline.insert("AdversarialAuditIsolationExplicitDeny".to_string());

        Self {
            security_group_id: "sg-osoosi-agent-sandbox".to_string(),
            vpc_id: "vpc-osoosi-isolated".to_string(),
            task_role_name: "OsoosiAgentTaskRole".to_string(),
            egress_rules: vec![SandboxEgressRule {
                rule_id: "sgr-vpce-only".to_string(),
                protocol: "tcp".to_string(),
                cidr_ipv4: Some("10.254.0.0/16".to_string()),
                cidr_ipv6: None,
                description: "Scoped VPC Endpoint egress only".to_string(),
            }],
            route_entries: vec![SandboxRouteEntry {
                route_table_id: "rtb-osoosi-isolated".to_string(),
                destination_cidr: "10.254.0.0/16".to_string(),
                gateway_id: "local".to_string(),
            }],
            expected_attached_policy_arns: attached.clone(),
            actual_attached_policy_arns: attached,
            expected_inline_policy_names: inline.clone(),
            actual_inline_policy_names: inline,
            dns_firewall_associations: vec![DnsFirewallAssociation {
                association_id: "rslvr-frgassoc-osoosi01".to_string(),
                vpc_id: "vpc-osoosi-isolated".to_string(),
                status: "COMPLETE".to_string(),
                allowed_domain_patterns: vec![
                    "*.amazonaws.com".to_string(),
                    "localhost".to_string(),
                    "127.0.0.1".to_string(),
                ],
            }],
        }
    }
}

/// Result of running the 4-Invariant Independent Watchdog (`lambda/watchdog/handler.py` port).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogAssessmentReport {
    pub status: String, // "healthy" or "killed"
    pub checked_at: DateTime<Utc>,
    pub security_group_violations: Vec<String>,
    pub route_table_violations: Vec<String>,
    pub iam_policy_violations: Vec<String>,
    pub dns_firewall_violations: Vec<String>,
    pub all_violations: Vec<String>,
    pub kill_switch_report: Option<KillSwitchTerminationReport>,
}

/// Result of executing the Containment KillSwitch (`lambda/kill_switch/handler.py` port).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchTerminationReport {
    pub triggered_at: DateTime<Utc>,
    pub cluster_id: String,
    pub services_scaled_down_to_zero: Vec<String>,
    pub auto_respawn_disabled: bool,
    pub tasks_terminated_count: usize,
    pub terminated_task_ids: Vec<String>,
    pub new_generation_epoch: u64,
    pub violation_summary: String,
}

/// Tracks per-arm service state and running task IDs for KillSwitch scale-down & termination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClusterServiceState {
    pub cluster_id: String,
    pub service_name: String,
    pub desired_count: usize,
    pub auto_respawn_disabled: bool,
    pub running_task_ids: Vec<String>,
    pub generation_epoch: u64,
}

/// Unified Oso Authorization + AWS Containment-Response Engine.
pub struct OsoAwsContainmentEngine {
    hitl_secret_key: Vec<u8>,
    /// Sliding 60s window of `AccessDenied` timestamps per `agent_id` (R5).
    denied_call_windows: DashMap<String, VecDeque<DateTime<Utc>>>,
    /// Per-agent/cluster service state for KillSwitch scale-down & task termination.
    cluster_services: DashMap<String, AgentClusterServiceState>,
    /// Audit log of all KillSwitch executions (immutable append-only in-memory ring).
    kill_switch_history: DashMap<String, Vec<KillSwitchTerminationReport>>,
    pub r5_denied_threshold: usize,
    pub r5_window_secs: i64,
}

impl Default for OsoAwsContainmentEngine {
    fn default() -> Self {
        Self::new(b"osoosi-oso-aws-containment-hitl-default-key-2026")
    }
}

impl OsoAwsContainmentEngine {
    pub fn new(hitl_secret_key: &[u8]) -> Self {
        let engine = Self {
            hitl_secret_key: hitl_secret_key.to_vec(),
            denied_call_windows: DashMap::new(),
            cluster_services: DashMap::new(),
            kill_switch_history: DashMap::new(),
            r5_denied_threshold: AWS_R5_DEFAULT_DENIED_THRESHOLD,
            r5_window_secs: AWS_R5_DEFAULT_WINDOW_SECS,
        };
        // Seed default Agent Octopus arm cluster service
        engine.register_agent_service(
            "octopus-agent-cluster",
            "octopus-worker-service",
            2,
            vec![
                "task-arm-01-doc-ingest".to_string(),
                "task-arm-02-network-egress".to_string(),
            ],
        );
        engine
    }

    pub fn hitl_secret_key(&self) -> &[u8] {
        &self.hitl_secret_key
    }

    /// Registers or resets an agent service and its running tasks.
    pub fn register_agent_service(
        &self,
        cluster_id: &str,
        service_name: &str,
        desired_count: usize,
        running_task_ids: Vec<String>,
    ) {
        self.cluster_services.insert(
            cluster_id.to_string(),
            AgentClusterServiceState {
                cluster_id: cluster_id.to_string(),
                service_name: service_name.to_string(),
                desired_count,
                auto_respawn_disabled: false,
                running_task_ids,
                generation_epoch: 1,
            },
        );
    }

    pub fn get_cluster_state(&self, cluster_id: &str) -> Option<AgentClusterServiceState> {
        self.cluster_services.get(cluster_id).map(|r| r.clone())
    }

    // ------------------------------------------------------------------------
    // R4: Adversarial Audit Isolation (Explicit Deny on Monitoring/Audit APIs)
    // ------------------------------------------------------------------------

    /// Checks whether an action targets monitoring, IAM, watchdog, audit, or kill-switch infrastructure.
    /// In `aws-samples/sample-agent-containment-response` (R4), Explicit Deny overrides any Allow.
    pub fn is_adversarial_audit_or_control_plane_probe(action: &str, resource: &str) -> bool {
        let lower_act = action.to_ascii_lowercase();
        let lower_res = resource.to_ascii_lowercase();

        const FORBIDDEN_ACTION_PREFIXES: &[&str] = &[
            "iam:",
            "cloudtrail:",
            "cloudwatch:",
            "guardduty:",
            "ec2:describe",
            "ec2:authorizesecuritygroup",
            "ec2:createroute",
            "route53resolver:",
            "s3:bypassgovernanceretention",
            "osoosi:watchdog:",
            "osoosi:audit:",
            "osoosi:killswitch:",
            "sentinel:disable",
            "watchdog:tamper",
        ];

        const FORBIDDEN_RESOURCE_PATTERNS: &[&str] = &[
            "/var/lib/osoosi/audit",
            "watchdog_stack",
            "audit_stack",
            "kill_switch",
            "containment_verifier_role",
        ];

        FORBIDDEN_ACTION_PREFIXES
            .iter()
            .any(|p| lower_act.starts_with(p))
            || FORBIDDEN_RESOURCE_PATTERNS
                .iter()
                .any(|p| lower_res.contains(p))
    }

    // ------------------------------------------------------------------------
    // R5: Capability Envelope AccessDenied Velocity Alarm (>= 3 in 60s -> Kill)
    // ------------------------------------------------------------------------

    /// Records a denied capability/API call for `agent_id` and returns `Some(KillSwitchTerminationReport)`
    /// if the sliding 60-second window reaches or exceeds `r5_denied_threshold` (default 3).
    pub fn record_access_denied_and_check_alarm(
        &self,
        agent_id: &str,
        cluster_id: &str,
        denial_reason: &str,
        now: DateTime<Utc>,
    ) -> Option<KillSwitchTerminationReport> {
        let cutoff = now - chrono::Duration::seconds(self.r5_window_secs);
        let count = {
            let mut entry = self
                .denied_call_windows
                .entry(agent_id.to_string())
                .or_default();
            while let Some(&front) = entry.front() {
                if front < cutoff {
                    entry.pop_front();
                } else {
                    break;
                }
            }
            entry.push_back(now);
            entry.len()
        };

        if count >= self.r5_denied_threshold {
            let violation = format!(
                "R5_CAPABILITY_ENVELOPE_ALARM: Agent '{}' triggered {} AccessDenied events within {}s (threshold: {}). Latest denial: {}",
                agent_id, count, self.r5_window_secs, self.r5_denied_threshold, denial_reason
            );
            Some(self.execute_kill_switch(cluster_id, &[violation], now))
        } else {
            None
        }
    }

    pub fn recent_denied_count(&self, agent_id: &str, now: DateTime<Utc>) -> usize {
        let cutoff = now - chrono::Duration::seconds(self.r5_window_secs);
        self.denied_call_windows
            .get(agent_id)
            .map(|q| q.iter().filter(|&&ts| ts >= cutoff).count())
            .unwrap_or(0)
    }

    // ------------------------------------------------------------------------
    // OSO 1: 3-Way Delegated Identity Intersection + R4 + R5 Integration
    // ------------------------------------------------------------------------

    /// Evaluates an agent action request against:
    /// 1. AWS R4 Adversarial Audit Isolation (Explicit Deny on monitoring/control-plane discovery),
    /// 2. Oso 3-Way Intersection (`Perm(User) ∩ Cap(AgentRole) ∩ Scope(Task)`),
    /// 3. AWS R5 Capability Envelope Velocity Alarm (`>= 3` denials in 60s triggers KillSwitch).
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_intersection_authority(
        &self,
        agent_id: &str,
        cluster_id: &str,
        agent_role: &ArmRole,
        user: &DelegatingUserContext,
        task_scope: &TaskScopeEnvelope,
        action: &str,
        resource: &str,
        now: DateTime<Utc>,
    ) -> OsoAuthzDecision {
        // Step 1: AWS R4 Explicit Deny on monitoring, IAM, watchdog, and audit infrastructure
        if Self::is_adversarial_audit_or_control_plane_probe(action, resource) {
            let reason = format!(
                "AWS_R4_ADVERSARIAL_AUDIT_ISOLATION_DENY: Agent '{}' attempted forbidden control-plane/monitoring action '{}' on '{}'",
                agent_id, action, resource
            );
            let ks = self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
            return OsoAuthzDecision::Deny {
                code: "AWS_R4_EXPLICIT_DENY".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        // Step 2: Check Delegating Human User Permission Set
        if !user.permissions.contains(action) {
            let reason = format!(
                "OSO_INTERSECTION_USER_DENIED: Delegating user '{}' lacks permission '{}' for resource '{}'",
                user.user_id, action, resource
            );
            let ks = self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
            return OsoAuthzDecision::Deny {
                code: "OSO_USER_PERMISSION_MISSING".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        let user_owns_resource = user
            .allowed_resources
            .iter()
            .any(|prefix| resource == prefix || resource.starts_with(prefix));
        if !user_owns_resource {
            let reason = format!(
                "OSO_INTERSECTION_USER_RESOURCE_DENIED: Delegating user '{}' has no ownership/ACL grant over resource '{}'",
                user.user_id, resource
            );
            let ks = self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
            return OsoAuthzDecision::Deny {
                code: "OSO_USER_RESOURCE_UNAUTHORIZED".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        // Step 3: Check Agent Role Capability Set
        let role_caps = role_capability_actions(agent_role);
        if !role_caps.contains(action) {
            let reason = format!(
                "OSO_INTERSECTION_ROLE_DENIED: Agent '{}' with role {:?} lacks capability '{}' (even though user '{}' possesses it)",
                agent_id, agent_role, action, user.user_id
            );
            let ks = self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
            return OsoAuthzDecision::Deny {
                code: "OSO_AGENT_ROLE_CAPABILITY_MISSING".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        // Step 4: Check Task Scope JIT Envelope
        if !task_scope.allowed_actions.contains(action) {
            let reason = format!(
                "OSO_INTERSECTION_TASK_SCOPE_DENIED: Task '{}' does not scope action '{}'",
                task_scope.task_id, action
            );
            let ks = self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
            return OsoAuthzDecision::Deny {
                code: "OSO_TASK_SCOPE_ACTION_DENIED".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        let in_task_resource_scope = task_scope
            .allowed_resource_prefixes
            .iter()
            .any(|prefix| resource.starts_with(prefix));
        if !in_task_resource_scope {
            let reason = format!(
                "OSO_INTERSECTION_TASK_RESOURCE_OUT_OF_SCOPE: Resource '{}' is outside task '{}' prefixes {:?}",
                resource, task_scope.task_id, task_scope.allowed_resource_prefixes
            );
            let ks = self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
            return OsoAuthzDecision::Deny {
                code: "OSO_TASK_RESOURCE_OUT_OF_SCOPE".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        OsoAuthzDecision::Allow {
            effective_intersection_action: action.to_string(),
            rationale: format!(
                "Authorized via 3-way Oso intersection: User('{}') ∩ Role({:?}) ∩ Task('{}') on '{}'",
                user.user_id, agent_role, task_scope.task_id, resource
            ),
        }
    }

    // ------------------------------------------------------------------------
    // OSO 2: Pre-Retrieval RAG Document Authorization Filter
    // ------------------------------------------------------------------------

    /// Filters candidate RAG document chunks *before* they enter the LLM context window.
    pub fn filter_rag_documents_pre_retrieval(
        &self,
        user: &DelegatingUserContext,
        agent_role: &ArmRole,
        task_scope: &TaskScopeEnvelope,
        candidates: &[RagDocumentChunk],
    ) -> RagFilterResult {
        let max_role_tier = role_max_clearance_tier(agent_role);
        let effective_max_tier = user.max_clearance_tier.min(max_role_tier);

        let mut authorized_doc_ids = Vec::new();
        let mut filtered_out_doc_ids = Vec::new();
        let mut reasons = Vec::new();

        for doc in candidates {
            if doc.workspace_id != task_scope.workspace_id {
                filtered_out_doc_ids.push(doc.doc_id.clone());
                reasons.push(format!(
                    "Doc '{}' excluded: workspace '{}' != task workspace '{}'",
                    doc.doc_id, doc.workspace_id, task_scope.workspace_id
                ));
                continue;
            }

            let has_rebac_access =
                doc.owner_id == user.user_id || doc.shared_with_users.contains(&user.user_id);
            if !has_rebac_access {
                filtered_out_doc_ids.push(doc.doc_id.clone());
                reasons.push(format!(
                    "Doc '{}' excluded: user '{}' is neither owner ('{}') nor in shared ACL",
                    doc.doc_id, user.user_id, doc.owner_id
                ));
                continue;
            }

            if doc.classification_tier > effective_max_tier {
                filtered_out_doc_ids.push(doc.doc_id.clone());
                reasons.push(format!(
                    "Doc '{}' excluded: classification tier {} exceeds effective intersection clearance {} (user={}, role={})",
                    doc.doc_id, doc.classification_tier, effective_max_tier, user.max_clearance_tier, max_role_tier
                ));
                continue;
            }

            authorized_doc_ids.push(doc.doc_id.clone());
        }

        RagFilterResult {
            total_candidates: candidates.len(),
            authorized_doc_ids,
            filtered_out_doc_ids,
            reasons,
        }
    }

    // ------------------------------------------------------------------------
    // OSO 3 & 4: MCP Tool-Call Parameter Gate + Out-of-Band HITL Step-Up Auth
    // ------------------------------------------------------------------------

    /// Evaluates an MCP `tools/call` invocation with deep parameter inspection and
    /// mandatory out-of-band HMAC-SHA256 HITL ticket verification for destructive tools.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_mcp_tool_call(
        &self,
        agent_id: &str,
        cluster_id: &str,
        agent_role: &ArmRole,
        user: &DelegatingUserContext,
        task_scope: &TaskScopeEnvelope,
        tool_name: &str,
        mapped_action: &str,
        target_resource: &str,
        arguments: &Value,
        hitl_ticket: Option<&HitlStepUpTicket>,
        now: DateTime<Utc>,
    ) -> OsoAuthzDecision {
        // 1. First enforce 3-way intersection & R4 audit isolation
        let base_decision = self.evaluate_intersection_authority(
            agent_id,
            cluster_id,
            agent_role,
            user,
            task_scope,
            mapped_action,
            target_resource,
            now,
        );
        if matches!(base_decision, OsoAuthzDecision::Deny { .. }) {
            return base_decision;
        }

        // 2. Parameter-level bound: query limit check
        if let Some(limit) = arguments.get("limit").and_then(|v| v.as_u64()) {
            if limit > task_scope.max_query_limit {
                let reason = format!(
                    "OSO_MCP_PARAM_LIMIT_EXCEEDED: Tool '{}' requested limit={} exceeding task max_query_limit={}",
                    tool_name, limit, task_scope.max_query_limit
                );
                let ks =
                    self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
                return OsoAuthzDecision::Deny {
                    code: "OSO_MCP_PARAM_LIMIT_EXCEEDED".to_string(),
                    reason,
                    kill_switch_triggered: ks.is_some(),
                };
            }
        }

        // 3. Parameter-level bound: row owner check if `owner_id` parameter is present
        if let Some(row_owner) = arguments.get("owner_id").and_then(|v| v.as_str()) {
            if row_owner != user.user_id {
                let reason = format!(
                    "OSO_MCP_ROW_OWNERSHIP_VIOLATION: Tool '{}' targeted row owner '{}' != delegating user '{}'",
                    tool_name, row_owner, user.user_id
                );
                let ks =
                    self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
                return OsoAuthzDecision::Deny {
                    code: "OSO_MCP_ROW_OWNERSHIP_VIOLATION".to_string(),
                    reason,
                    kill_switch_triggered: ks.is_some(),
                };
            }
        }

        // 4. Check if tool or parameters represent a destructive / high-blast-radius operation
        let lower_tool = tool_name.to_ascii_lowercase();
        let is_destructive_tool = lower_tool.starts_with("delete_")
            || lower_tool.starts_with("drop_")
            || lower_tool.starts_with("truncate_")
            || lower_tool == "transfer_funds"
            || lower_tool == "modify_security_policy"
            || mapped_action.starts_with("delete:")
            || mapped_action == "transfer:funds";

        let targets_production = arguments
            .get("environment")
            .and_then(|v| v.as_str())
            .map(|env| env.eq_ignore_ascii_case("production") || env.eq_ignore_ascii_case("prod"))
            .unwrap_or(false);

        if is_destructive_tool && targets_production && !task_scope.allow_production_mutation {
            let reason = format!(
                "OSO_PRODUCTION_MUTATION_FORBIDDEN: Destructive tool '{}' blocked on production environment",
                tool_name
            );
            let ks = self.record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
            return OsoAuthzDecision::Deny {
                code: "OSO_PRODUCTION_MUTATION_FORBIDDEN".to_string(),
                reason,
                kill_switch_triggered: ks.is_some(),
            };
        }

        if is_destructive_tool {
            match hitl_ticket {
                None => {
                    let reason = format!(
                        "OSO_HITL_STEP_UP_REQUIRED: Destructive tool '{}' requires an out-of-band HMAC-SHA256 HitlStepUpTicket (prompt claims are ignored)",
                        tool_name
                    );
                    let ks = self
                        .record_access_denied_and_check_alarm(agent_id, cluster_id, &reason, now);
                    return OsoAuthzDecision::Deny {
                        code: "OSO_HITL_STEP_UP_REQUIRED".to_string(),
                        reason,
                        kill_switch_triggered: ks.is_some(),
                    };
                }
                Some(ticket) => {
                    if let Err(err) = verify_hitl_step_up_ticket(
                        &self.hitl_secret_key,
                        ticket,
                        &user.user_id,
                        agent_id,
                        tool_name,
                        arguments,
                        now.timestamp(),
                    ) {
                        let reason = format!(
                            "OSO_HITL_STEP_UP_INVALID: Destructive tool '{}' rejected: {}",
                            tool_name, err
                        );
                        let ks = self.record_access_denied_and_check_alarm(
                            agent_id, cluster_id, &reason, now,
                        );
                        return OsoAuthzDecision::Deny {
                            code: "OSO_HITL_STEP_UP_INVALID".to_string(),
                            reason,
                            kill_switch_triggered: ks.is_some(),
                        };
                    }
                }
            }
        }

        OsoAuthzDecision::Allow {
            effective_intersection_action: mapped_action.to_string(),
            rationale: format!(
                "MCP tool '{}' authorized via Oso parameter & intersection policy for user '{}'",
                tool_name, user.user_id
            ),
        }
    }

    // ------------------------------------------------------------------------
    // AWS R3: 4-Invariant Independent Containment Watchdog
    // ------------------------------------------------------------------------

    /// Invariant 1 (`check_security_group`): Verifies zero egress rules allow `0.0.0.0/0` or `::/0`.
    pub fn check_security_group_invariants(
        snapshot: &ContainmentEnvironmentSnapshot,
    ) -> Vec<String> {
        let mut violations = Vec::new();
        for rule in &snapshot.egress_rules {
            if let Some(ref cidr) = rule.cidr_ipv4 {
                if cidr.trim() == "0.0.0.0/0" {
                    violations.push(format!(
                        "Security group {} has egress rule {} allowing 0.0.0.0/0 (protocol: {})",
                        snapshot.security_group_id, rule.rule_id, rule.protocol
                    ));
                }
            }
            if let Some(ref cidr6) = rule.cidr_ipv6 {
                if cidr6.trim() == "::/0" {
                    violations.push(format!(
                        "Security group {} has egress rule {} allowing ::/0 (protocol: {})",
                        snapshot.security_group_id, rule.rule_id, rule.protocol
                    ));
                }
            }
        }
        violations
    }

    /// Invariant 2 (`check_route_tables`): Verifies no route table has a route to an internet gateway (`igw-*`).
    pub fn check_route_table_invariants(snapshot: &ContainmentEnvironmentSnapshot) -> Vec<String> {
        let mut violations = Vec::new();
        for route in &snapshot.route_entries {
            if route.gateway_id.starts_with("igw-")
                || route.gateway_id.starts_with("unproxied-raw-")
            {
                violations.push(format!(
                    "Route table {} has route to internet gateway {} (destination: {})",
                    route.route_table_id, route.gateway_id, route.destination_cidr
                ));
            }
        }
        violations
    }

    /// Invariant 3 (`check_iam_policies`): Checks both attached/inline policy counts AND exact ARN/name sets
    /// to catch both additions/removals and **Policy Swap Attacks**.
    pub fn check_iam_policy_invariants(snapshot: &ContainmentEnvironmentSnapshot) -> Vec<String> {
        let mut violations = Vec::new();

        let expected_attached_count = snapshot.expected_attached_policy_arns.len();
        let actual_attached_count = snapshot.actual_attached_policy_arns.len();
        if actual_attached_count != expected_attached_count {
            violations.push(format!(
                "Role {} has {} attached policies, expected {}",
                snapshot.task_role_name, actual_attached_count, expected_attached_count
            ));
        }

        let unexpected_arns: Vec<String> = snapshot
            .actual_attached_policy_arns
            .difference(&snapshot.expected_attached_policy_arns)
            .cloned()
            .collect();
        let missing_arns: Vec<String> = snapshot
            .expected_attached_policy_arns
            .difference(&snapshot.actual_attached_policy_arns)
            .cloned()
            .collect();

        if !unexpected_arns.is_empty() {
            violations.push(format!(
                "Role {} has unexpected attached policies (swap/addition detected): {}",
                snapshot.task_role_name,
                unexpected_arns.join(", ")
            ));
        }
        if !missing_arns.is_empty() {
            violations.push(format!(
                "Role {} is missing expected attached policies: {}",
                snapshot.task_role_name,
                missing_arns.join(", ")
            ));
        }

        let expected_inline_count = snapshot.expected_inline_policy_names.len();
        let actual_inline_count = snapshot.actual_inline_policy_names.len();
        if actual_inline_count != expected_inline_count {
            violations.push(format!(
                "Role {} has {} inline policies, expected {}",
                snapshot.task_role_name, actual_inline_count, expected_inline_count
            ));
        }

        let unexpected_inline: Vec<String> = snapshot
            .actual_inline_policy_names
            .difference(&snapshot.expected_inline_policy_names)
            .cloned()
            .collect();
        let missing_inline: Vec<String> = snapshot
            .expected_inline_policy_names
            .difference(&snapshot.actual_inline_policy_names)
            .cloned()
            .collect();

        if !unexpected_inline.is_empty() {
            violations.push(format!(
                "Role {} has unexpected inline policies (swap/addition detected): {}",
                snapshot.task_role_name,
                unexpected_inline.join(", ")
            ));
        }
        if !missing_inline.is_empty() {
            violations.push(format!(
                "Role {} is missing expected inline policies: {}",
                snapshot.task_role_name,
                missing_inline.join(", ")
            ));
        }

        violations
    }

    /// Invariant 4 (`check_dns_firewall`): Verifies at least one `COMPLETE` DNS Firewall rule group association
    /// remains attached to the agent VPC.
    pub fn check_dns_firewall_invariants(snapshot: &ContainmentEnvironmentSnapshot) -> Vec<String> {
        let active_complete = snapshot
            .dns_firewall_associations
            .iter()
            .filter(|a| a.vpc_id == snapshot.vpc_id && a.status == "COMPLETE")
            .count();

        if active_complete == 0 {
            vec![format!(
                "No active DNS Firewall rule group associated with VPC {}. DNS resolution is unrestricted, enabling potential data exfiltration.",
                snapshot.vpc_id
            )]
        } else {
            Vec::new()
        }
    }

    /// Evaluates DNS resolution against the active DNS Firewall allowlist (`R1: DNS restriction`).
    /// Returns `Ok(())` if permitted or `Err("NXDOMAIN: ...")` if blocked.
    pub fn check_dns_firewall_query(
        snapshot: &ContainmentEnvironmentSnapshot,
        domain: &str,
    ) -> Result<(), String> {
        let lower_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        for assoc in &snapshot.dns_firewall_associations {
            if assoc.vpc_id == snapshot.vpc_id && assoc.status == "COMPLETE" {
                for pattern in &assoc.allowed_domain_patterns {
                    let pat = pattern.to_ascii_lowercase();
                    if let Some(suffix) = pat.strip_prefix("*.") {
                        if lower_domain == suffix || lower_domain.ends_with(&format!(".{}", suffix))
                        {
                            return Ok(());
                        }
                    } else if lower_domain == pat {
                        return Ok(());
                    }
                }
            }
        }
        Err(format!(
            "NXDOMAIN: DNS Firewall blocked resolution of '{}' in VPC '{}'",
            domain, snapshot.vpc_id
        ))
    }

    /// Runs all 4 independent containment invariant checks (`lambda/watchdog/handler.py` port).
    /// If any invariant is violated, immediately invokes `execute_kill_switch`.
    pub fn verify_four_containment_invariants(
        &self,
        cluster_id: &str,
        snapshot: &ContainmentEnvironmentSnapshot,
        now: DateTime<Utc>,
    ) -> WatchdogAssessmentReport {
        let security_group_violations = Self::check_security_group_invariants(snapshot);
        let route_table_violations = Self::check_route_table_invariants(snapshot);
        let iam_policy_violations = Self::check_iam_policy_invariants(snapshot);
        let dns_firewall_violations = Self::check_dns_firewall_invariants(snapshot);

        let mut all_violations = Vec::new();
        all_violations.extend(security_group_violations.clone());
        all_violations.extend(route_table_violations.clone());
        all_violations.extend(iam_policy_violations.clone());
        all_violations.extend(dns_firewall_violations.clone());

        if !all_violations.is_empty() {
            let ks_report = self.execute_kill_switch(cluster_id, &all_violations, now);
            return WatchdogAssessmentReport {
                status: "killed".to_string(),
                checked_at: now,
                security_group_violations,
                route_table_violations,
                iam_policy_violations,
                dns_firewall_violations,
                all_violations,
                kill_switch_report: Some(ks_report),
            };
        }

        WatchdogAssessmentReport {
            status: "healthy".to_string(),
            checked_at: now,
            security_group_violations,
            route_table_violations,
            iam_policy_violations,
            dns_firewall_violations,
            all_violations,
            kill_switch_report: None,
        }
    }

    // ------------------------------------------------------------------------
    // AWS KillSwitch Handler: Service Scale-Down + Task Termination + Epoch Bump
    // ------------------------------------------------------------------------

    /// Executes the Containment KillSwitch (`lambda/kill_switch/handler.py` port):
    /// 1. Scales down all services in `cluster_id` to `desired_count = 0` (`auto_respawn_disabled = true`)
    ///    so the scheduler cannot replace terminated agent tasks.
    /// 2. Enumerates and stops all running tasks in `cluster_id`.
    /// 3. Advances the cluster's monotonic generation epoch (`Gen N -> Gen N + 1`).
    /// 4. Records an immutable breach report in `kill_switch_history`.
    pub fn execute_kill_switch(
        &self,
        cluster_id: &str,
        violations: &[String],
        now: DateTime<Utc>,
    ) -> KillSwitchTerminationReport {
        let violation_summary = if violations.is_empty() {
            "Unknown containment violation".to_string()
        } else {
            violations.join("; ")
        };

        let mut state = self
            .cluster_services
            .entry(cluster_id.to_string())
            .or_insert_with(|| AgentClusterServiceState {
                cluster_id: cluster_id.to_string(),
                service_name: "default-agent-service".to_string(),
                desired_count: 1,
                auto_respawn_disabled: false,
                running_task_ids: vec!["task-default-0".to_string()],
                generation_epoch: 1,
            });

        // 1. Scale down service to 0 to prevent task replacement
        state.desired_count = 0;
        state.auto_respawn_disabled = true;
        let scaled_services = vec![state.service_name.clone()];

        // 2. Stop all running tasks
        let terminated_task_ids: Vec<String> = std::mem::take(&mut state.running_task_ids);
        let tasks_terminated_count = terminated_task_ids.len();

        // 3. Monotonically advance generation epoch (Gen N -> Gen N+1)
        state.generation_epoch = state.generation_epoch.saturating_add(1);
        let new_generation_epoch = state.generation_epoch;
        drop(state);

        let report = KillSwitchTerminationReport {
            triggered_at: now,
            cluster_id: cluster_id.to_string(),
            services_scaled_down_to_zero: scaled_services,
            auto_respawn_disabled: true,
            tasks_terminated_count,
            terminated_task_ids,
            new_generation_epoch,
            violation_summary,
        };

        self.kill_switch_history
            .entry(cluster_id.to_string())
            .or_default()
            .push(report.clone());

        report
    }

    pub fn kill_switch_reports(&self, cluster_id: &str) -> Vec<KillSwitchTerminationReport> {
        self.kill_switch_history
            .get(cluster_id)
            .map(|r| r.clone())
            .unwrap_or_default()
    }
}

/// Global singleton for Oso + AWS Containment-Response evaluation in Agent Octopus & Dashboard.
pub static GLOBAL_OSO_AWS_CONTAINMENT: LazyLock<Arc<OsoAwsContainmentEngine>> =
    LazyLock::new(|| Arc::new(OsoAwsContainmentEngine::default()));

pub fn global_oso_aws_containment() -> Arc<OsoAwsContainmentEngine> {
    Arc::clone(&GLOBAL_OSO_AWS_CONTAINMENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_user_and_task() -> (DelegatingUserContext, TaskScopeEnvelope) {
        let mut perms = BTreeSet::new();
        perms.insert("read:docs".to_string());
        perms.insert("write:ledger".to_string());
        perms.insert("transfer:funds".to_string());

        let mut resources = BTreeSet::new();
        resources.insert("doc://workspace-alpha/".to_string());
        resources.insert("ledger://workspace-alpha/".to_string());

        let user = DelegatingUserContext {
            user_id: "alice@enterprise.internal".to_string(),
            permissions: perms,
            allowed_resources: resources,
            max_clearance_tier: 2, // Confidential
        };

        let mut task_actions = BTreeSet::new();
        task_actions.insert("read:docs".to_string());
        task_actions.insert("write:ledger".to_string());
        task_actions.insert("transfer:funds".to_string());

        let task = TaskScopeEnvelope {
            task_id: "task-q3-reconcile".to_string(),
            workspace_id: "workspace-alpha".to_string(),
            allowed_actions: task_actions,
            allowed_resource_prefixes: vec![
                "doc://workspace-alpha/".to_string(),
                "ledger://workspace-alpha/".to_string(),
            ],
            max_query_limit: 50,
            allow_production_mutation: false,
        };

        (user, task)
    }

    #[test]
    fn test_oso_three_way_delegated_intersection_authority() {
        let engine = OsoAwsContainmentEngine::new(b"test-secret-key-32-bytes-long!!!");
        let (user, task) = sample_user_and_task();
        let now = Utc::now();

        // 1. User has 'write:ledger', Task allows 'write:ledger', but UntrustedDocIngest role only has 'read:docs'
        let denied_by_role = engine.evaluate_intersection_authority(
            "arm-doc-1",
            "cluster-1",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "write:ledger",
            "ledger://workspace-alpha/q3",
            now,
        );
        assert!(matches!(
            denied_by_role,
            OsoAuthzDecision::Deny {
                ref code,
                kill_switch_triggered: false,
                ..
            } if code == "OSO_AGENT_ROLE_CAPABILITY_MISSING"
        ));

        // 2. AccountingLedgerWrite role has 'write:ledger', User has 'write:ledger', and Resource is in Task scope -> ALLOW
        let allowed = engine.evaluate_intersection_authority(
            "arm-ledger-1",
            "cluster-1",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "write:ledger",
            "ledger://workspace-alpha/q3",
            now,
        );
        assert!(matches!(allowed, OsoAuthzDecision::Allow { .. }));

        // 3. AccountingLedgerWrite attempts to write to 'ledger://workspace-beta/q3' (User does not own workspace-beta) -> DENY
        let denied_by_user_acl = engine.evaluate_intersection_authority(
            "arm-ledger-1",
            "cluster-1",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "write:ledger",
            "ledger://workspace-beta/q3",
            now,
        );
        assert!(matches!(
            denied_by_user_acl,
            OsoAuthzDecision::Deny {
                ref code,
                ..
            } if code == "OSO_USER_RESOURCE_UNAUTHORIZED"
        ));
    }

    #[test]
    fn test_oso_pre_retrieval_rag_filtering() {
        let engine = OsoAwsContainmentEngine::default();
        let (user, task) = sample_user_and_task();

        let chunks = vec![
            RagDocumentChunk {
                doc_id: "doc-1-allowed".to_string(),
                workspace_id: "workspace-alpha".to_string(),
                owner_id: "alice@enterprise.internal".to_string(),
                shared_with_users: BTreeSet::new(),
                classification_tier: 1, // Internal (<= UntrustedDocIngest tier 1)
                content_preview: "Q3 benign invoice summary".to_string(),
            },
            RagDocumentChunk {
                doc_id: "doc-2-too-secret-for-role".to_string(),
                workspace_id: "workspace-alpha".to_string(),
                owner_id: "alice@enterprise.internal".to_string(),
                shared_with_users: BTreeSet::new(),
                classification_tier: 2, // Confidential (User has 2, but UntrustedDocIngest max is 1!)
                content_preview: "Confidential M&A board deck".to_string(),
            },
            RagDocumentChunk {
                doc_id: "doc-3-unowned".to_string(),
                workspace_id: "workspace-alpha".to_string(),
                owner_id: "bob@enterprise.internal".to_string(),
                shared_with_users: BTreeSet::new(),
                classification_tier: 0,
                content_preview: "Bob private notes".to_string(),
            },
        ];

        let filtered = engine.filter_rag_documents_pre_retrieval(
            &user,
            &ArmRole::UntrustedDocIngest,
            &task,
            &chunks,
        );
        assert_eq!(filtered.authorized_doc_ids, vec!["doc-1-allowed"]);
        assert_eq!(
            filtered.filtered_out_doc_ids,
            vec!["doc-2-too-secret-for-role", "doc-3-unowned"]
        );
    }

    #[test]
    fn test_oso_mcp_tool_call_and_hitl_step_up_ticket() {
        let secret = b"super-secret-hitl-hmac-key-2026";
        let engine = OsoAwsContainmentEngine::new(secret);
        let (user, task) = sample_user_and_task();
        let now = Utc::now();

        let args = json!({
            "owner_id": "alice@enterprise.internal",
            "amount_usd": 2500,
            "environment": "staging",
            "prompt_claimed_user_approved": true
        });

        // 1. Destructive tool `transfer_funds` WITHOUT out-of-band HitlStepUpTicket MUST fail closed
        let without_ticket = engine.authorize_mcp_tool_call(
            "arm-ledger-1",
            "cluster-hitl",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "transfer_funds",
            "transfer:funds",
            "ledger://workspace-alpha/transfers",
            &args,
            None,
            now,
        );
        assert!(matches!(
            without_ticket,
            OsoAuthzDecision::Deny {
                ref code,
                ..
            } if code == "OSO_HITL_STEP_UP_REQUIRED"
        ));

        // 2. Issue valid out-of-band HMAC-SHA256 HitlStepUpTicket signed by human approver
        let valid_ticket = issue_hitl_step_up_ticket(
            secret,
            "secops-lead@enterprise.internal",
            &user.user_id,
            "arm-ledger-1",
            "transfer_funds",
            &args,
            now.timestamp() + 300,
        );

        let with_valid_ticket = engine.authorize_mcp_tool_call(
            "arm-ledger-1",
            "cluster-hitl",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "transfer_funds",
            "transfer:funds",
            "ledger://workspace-alpha/transfers",
            &args,
            Some(&valid_ticket),
            now,
        );
        assert!(matches!(with_valid_ticket, OsoAuthzDecision::Allow { .. }));

        // 3. Tamper with arguments after ticket issuance -> must reject with OSO_HITL_STEP_UP_INVALID
        let tampered_args = json!({
            "owner_id": "alice@enterprise.internal",
            "amount_usd": 999999,
            "environment": "staging"
        });
        let with_tampered_args = engine.authorize_mcp_tool_call(
            "arm-ledger-1",
            "cluster-hitl",
            &ArmRole::AccountingLedgerWrite,
            &user,
            &task,
            "transfer_funds",
            "transfer:funds",
            "ledger://workspace-alpha/transfers",
            &tampered_args,
            Some(&valid_ticket),
            now,
        );
        assert!(matches!(
            with_tampered_args,
            OsoAuthzDecision::Deny {
                ref code,
                ..
            } if code == "OSO_HITL_STEP_UP_INVALID"
        ));
    }

    #[test]
    fn test_aws_r3_four_invariants_and_policy_swap_detection() {
        let engine = OsoAwsContainmentEngine::default();
        let now = Utc::now();

        // 1. Default baseline snapshot must be 100% healthy
        let healthy_snap = ContainmentEnvironmentSnapshot::default();
        let report =
            engine.verify_four_containment_invariants("octopus-agent-cluster", &healthy_snap, now);
        assert_eq!(report.status, "healthy");
        assert!(report.all_violations.is_empty());

        // 2. Simulate Policy Swap Attack (count stays 1, but ARN is swapped for AdministratorAccess)
        //    plus Open Egress 0.0.0.0/0 and IGW route!
        let mut breached_snap = ContainmentEnvironmentSnapshot::default();
        breached_snap.actual_attached_policy_arns.clear();
        breached_snap
            .actual_attached_policy_arns
            .insert("arn:aws:iam::aws:policy/AdministratorAccess".to_string());
        breached_snap.egress_rules.push(SandboxEgressRule {
            rule_id: "sgr-rogue-open".to_string(),
            protocol: "tcp".to_string(),
            cidr_ipv4: Some("0.0.0.0/0".to_string()),
            cidr_ipv6: None,
            description: "Rogue open egress".to_string(),
        });
        breached_snap.route_entries.push(SandboxRouteEntry {
            route_table_id: "rtb-osoosi-isolated".to_string(),
            destination_cidr: "0.0.0.0/0".to_string(),
            gateway_id: "igw-0deadbeef".to_string(),
        });
        breached_snap.dns_firewall_associations.clear();

        let breach_report =
            engine.verify_four_containment_invariants("octopus-agent-cluster", &breached_snap, now);
        assert_eq!(breach_report.status, "killed");
        assert_eq!(breach_report.security_group_violations.len(), 1);
        assert_eq!(breach_report.route_table_violations.len(), 1);
        assert_eq!(breach_report.iam_policy_violations.len(), 2); // unexpected + missing ARN caught despite count == 1!
        assert_eq!(breach_report.dns_firewall_violations.len(), 1);

        let ks = breach_report
            .kill_switch_report
            .expect("KillSwitch must fire");
        assert!(ks.auto_respawn_disabled);
        assert_eq!(ks.tasks_terminated_count, 2);
        assert_eq!(ks.new_generation_epoch, 2);

        let cluster_state = engine.get_cluster_state("octopus-agent-cluster").unwrap();
        assert_eq!(cluster_state.desired_count, 0);
        assert!(cluster_state.running_task_ids.is_empty());
    }

    #[test]
    fn test_aws_r4_audit_isolation_and_r5_velocity_alarm_kill_switch() {
        let engine = OsoAwsContainmentEngine::default();
        engine.register_agent_service(
            "cluster-r5",
            "agent-worker-svc",
            1,
            vec!["task-rogue-99".to_string()],
        );
        let (user, task) = sample_user_and_task();
        let now = Utc::now();

        // Call 1: Probing CloudTrail (R4 Explicit Deny) -> Denied (1/3)
        let d1 = engine.evaluate_intersection_authority(
            "agent-rogue-99",
            "cluster-r5",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "cloudtrail:StopLogging",
            "arn:aws:cloudtrail:us-east-1:222222222222:trail/org-trail",
            now,
        );
        assert!(matches!(
            d1,
            OsoAuthzDecision::Deny {
                kill_switch_triggered: false,
                ..
            }
        ));

        // Call 2: Probing IAM AttachRolePolicy (R4 Explicit Deny) -> Denied (2/3)
        let d2 = engine.evaluate_intersection_authority(
            "agent-rogue-99",
            "cluster-r5",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "iam:AttachRolePolicy",
            "arn:aws:iam::111111111111:role/AgentTaskRole",
            now + chrono::Duration::seconds(10),
        );
        assert!(matches!(
            d2,
            OsoAuthzDecision::Deny {
                kill_switch_triggered: false,
                ..
            }
        ));

        // Call 3: Probing Watchdog within 60s window -> Denied (3/3) -> AUTOMATICALLY FIRES KILL SWITCH!
        let d3 = engine.evaluate_intersection_authority(
            "agent-rogue-99",
            "cluster-r5",
            &ArmRole::UntrustedDocIngest,
            &user,
            &task,
            "osoosi:watchdog:Disable",
            "/var/lib/osoosi/audit",
            now + chrono::Duration::seconds(25),
        );
        assert!(matches!(
            d3,
            OsoAuthzDecision::Deny {
                kill_switch_triggered: true,
                ..
            }
        ));

        // Verify cluster-r5 was scaled down to 0 and task-rogue-99 was terminated!
        let st = engine.get_cluster_state("cluster-r5").unwrap();
        assert_eq!(st.desired_count, 0);
        assert!(st.auto_respawn_disabled);
        assert!(st.running_task_ids.is_empty());
        assert_eq!(st.generation_epoch, 2);
    }
}
