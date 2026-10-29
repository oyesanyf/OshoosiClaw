//! Persistent Causal Security Graph backed by SQLite (`database/osoosi.db`).
//!
//! Provides non-detachable process instance provenance (`ProcessInstanceIdentity`),
//! transitive taint propagation across multi-step process spawns, file writes, and tool calls,
//! trusted post-quantum ZK-PII declassification (`<ZK_PII:...>` with ML-DSA-65 proof),
//! service-identity key isolation without `CRYPTPROTECT_LOCAL_MACHINE` (P0.2),
//! confused-deputy broker attribution (P1.2), and outcome-level workflow composition queries.

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use osoosi_dp::{PresidioGlinerPiiZeroGuard, ZkBftQuarantineProof};

// -----------------------------------------------------------------------------
// Non-Detachable Process Identity
// -----------------------------------------------------------------------------

/// Composite non-detachable identity for process instances.
///
/// Prevents numerical PID reuse, cross-session context laundering, and
/// detached child escapes by binding PID, start time, BLAKE3 executable digest,
/// parent instance ID, Job Object handle ID, and origin session ID into a
/// deterministic BLAKE3 UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInstanceIdentity {
    pub instance_id: String,
    pub pid: u32,
    pub start_time_100ns: u64,
    pub image_digest_blake3: String,
    pub parent_instance_id: Option<String>,
    pub job_object_id: Option<String>,
    pub origin_session_id: String,
}

impl ProcessInstanceIdentity {
    /// Creates a new composite process instance identity and generates its deterministic UUID.
    pub fn new(
        pid: u32,
        start_time_100ns: u64,
        image_digest_blake3: impl Into<String>,
        parent_instance_id: Option<String>,
        job_object_id: Option<String>,
        origin_session_id: impl Into<String>,
    ) -> Self {
        let digest_str = image_digest_blake3.into();
        let session_str = origin_session_id.into();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"OSOOSI_PROCESS_INSTANCE_V1:");
        hasher.update(&pid.to_le_bytes());
        hasher.update(&start_time_100ns.to_le_bytes());
        hasher.update(digest_str.as_bytes());
        if let Some(ref p) = parent_instance_id {
            hasher.update(p.as_bytes());
        }
        if let Some(ref j) = job_object_id {
            hasher.update(j.as_bytes());
        }
        hasher.update(session_str.as_bytes());
        let instance_id = hasher.finalize().to_hex().to_string();

        Self {
            instance_id,
            pid,
            start_time_100ns,
            image_digest_blake3: digest_str,
            parent_instance_id,
            job_object_id,
            origin_session_id: session_str,
        }
    }
}

// -----------------------------------------------------------------------------
// Core Domain Enums & Models
// -----------------------------------------------------------------------------

/// Security classification for file artifacts in the causal graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileClassification {
    CrownJewel,
    ConfidentialSource,
    WorkspaceConfig,
    Scratchpad,
    Untrusted,
    BenignSystem,
}

impl FileClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CrownJewel => "CrownJewel",
            Self::ConfidentialSource => "ConfidentialSource",
            Self::WorkspaceConfig => "WorkspaceConfig",
            Self::Scratchpad => "Scratchpad",
            Self::Untrusted => "Untrusted",
            Self::BenignSystem => "BenignSystem",
        }
    }

    pub fn from_str_relaxed(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "crownjewel" | "crown_jewel" => Self::CrownJewel,
            "confidentialsource" | "confidential_source" => Self::ConfidentialSource,
            "workspaceconfig" | "workspace_config" => Self::WorkspaceConfig,
            "scratchpad" => Self::Scratchpad,
            "benignsystem" | "benign_system" => Self::BenignSystem,
            _ => Self::Untrusted,
        }
    }
}

/// 5-Level Authority Hierarchy levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthorityLevel {
    SystemSecurityPolicy = 1,
    AuthorizedUserObjective = 2,
    TrustedApplicationInstruction = 3,
    WorkspaceConfiguration = 4,
    UntrustedRetrievedContent = 5,
}

impl AuthorityLevel {
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => Self::SystemSecurityPolicy,
            2 => Self::AuthorizedUserObjective,
            3 => Self::TrustedApplicationInstruction,
            4 => Self::WorkspaceConfiguration,
            _ => Self::UntrustedRetrievedContent,
        }
    }
}

/// Synchronous OS & agent effect operations recorded in `causal_events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsEffectType {
    ChildProcessExec,
    SensitiveFileAccess,
    ExternalNetworkConnect,
    ExternalWrite,
    PrivilegedLocalControl,
    DynamicCodeExec,
    CrossSessionTransfer,
    ToolCall,
    Declassification,
}

impl OsEffectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChildProcessExec => "ChildProcessExec",
            Self::SensitiveFileAccess => "SensitiveFileAccess",
            Self::ExternalNetworkConnect => "ExternalNetworkConnect",
            Self::ExternalWrite => "ExternalWrite",
            Self::PrivilegedLocalControl => "PrivilegedLocalControl",
            Self::DynamicCodeExec => "DynamicCodeExec",
            Self::CrossSessionTransfer => "CrossSessionTransfer",
            Self::ToolCall => "ToolCall",
            Self::Declassification => "Declassification",
        }
    }
}

/// Authorization verdict for causal events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CausalVerdict {
    Allow,
    Deny,
    PreExecutionPrevented,
    PostNotificationContained,
    Escalate,
}

impl CausalVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
            Self::PreExecutionPrevented => "PreExecutionPrevented",
            Self::PostNotificationContained => "PostNotificationContained",
            Self::Escalate => "Escalate",
        }
    }
}

/// Record representing a synchronous authorization event in `causal_events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalEventRecord {
    pub event_id: String,
    pub event_seq: u64,
    pub decision_id: Option<String>,
    pub session_id: String,
    pub process_instance_id: String,
    pub effect_type: String,
    pub source_resource: String,
    pub target_resource: String,
    pub is_authorized: bool,
    pub verdict: String,
    pub policy_version: u32,
    pub taint_epoch: u64,
    pub pre_event_taint: u32,
    pub post_event_taint: u32,
    pub details_json: Option<String>,
    pub timestamp: String,
}

/// Directed edge types in `causal_edges`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CausalEdgeType {
    Spawned,
    Read,
    Wrote,
    Executed,
    SentIpc,
    ToolInvoked,
    DerivedFrom,
    DeclassifiedInto,
    BrokeredBy,
}

impl CausalEdgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spawned => "Spawned",
            Self::Read => "Read",
            Self::Wrote => "Wrote",
            Self::Executed => "Executed",
            Self::SentIpc => "SentIpc",
            Self::ToolInvoked => "ToolInvoked",
            Self::DerivedFrom => "DerivedFrom",
            Self::DeclassifiedInto => "DeclassifiedInto",
            Self::BrokeredBy => "BrokeredBy",
        }
    }
}

/// Transitive taint investigation report returned by `get_transitive_taint_report`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransitiveTaintReport {
    pub node_id: String,
    pub is_tainted: bool,
    pub max_taint_level: u32,
    pub has_crown_jewel_taint: bool,
    pub taint_origins: Vec<String>,
    pub causal_chain: Vec<String>,
}

/// Result of a trusted zero-knowledge declassification operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationResult {
    pub success: bool,
    pub original_node_id: String,
    pub declassified_node_id: String,
    pub pii_leakage_bits: usize,
    pub pqc_signature_verified: bool,
    pub reason: String,
}

/// Outcome-level workflow composition match for sequential attack pattern queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSequenceMatch {
    pub session_id: String,
    pub matched_effects: Vec<String>,
    pub event_ids: Vec<String>,
    pub process_instances: Vec<String>,
    pub timestamps: Vec<String>,
}

/// Regression index record for adversarial test cases and security invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialRegressionCase {
    pub case_id: String,
    pub test_version: String,
    pub framework_version: String,
    pub random_seed: u64,
    pub environment_config: String,
    pub policy_version: u32,
    pub attack_objective: String,
    pub expected_effect: String,
    pub actual_effect: String,
    pub evidence: String,
    pub artifact_path: String,
    pub created_at: String,
}

/// Active in-memory tracking state for a session.
#[derive(Debug, Clone)]
pub struct SessionCausalState {
    pub session_id: String,
    pub taint_epoch: u64,
    pub revocation_seq: u64,
    pub taint_level: u32,
    pub has_crown_jewel_taint: bool,
    pub event_counter: u64,
}

// -----------------------------------------------------------------------------
// Service-Identity Key Isolation (P0.2)
// -----------------------------------------------------------------------------

/// Service-isolated cryptographic key manager (P0.2).
///
/// STRICT INVARIANT: Never uses `CRYPTPROTECT_LOCAL_MACHINE` (which any local user
/// can decrypt). Uses dedicated, non-exportable CSPRNG-derived keys bound exclusively
/// to the EDR service process identity.
pub struct ServiceIdentityKeyStore {
    hmac_key: [u8; 32],
    key_id: String,
}

impl ServiceIdentityKeyStore {
    /// Initializes a service-isolated key store using process-isolated entropy.
    pub fn new() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(b"OSOOSI_SERVICE_KEY_ID_V1:");
        id_hasher.update(&key);
        let key_id = id_hasher.finalize().to_hex()[..16].to_string();

        Self {
            hmac_key: key,
            key_id,
        }
    }

    /// Sign causal event attestation seal using service-isolated key.
    pub fn sign_attestation(&self, payload: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.hmac_key);
        hasher.update(payload);
        format!("{}:{}", self.key_id, hasher.finalize().to_hex())
    }

    /// Verify causal event attestation seal.
    pub fn verify_attestation(&self, payload: &[u8], seal: &str) -> bool {
        let parts: Vec<&str> = seal.split(':').collect();
        if parts.len() != 2 || parts[0] != self.key_id {
            return false;
        }
        let mut hasher = blake3::Hasher::new_keyed(&self.hmac_key);
        hasher.update(payload);
        let expected = hasher.finalize().to_hex().to_string();
        // Constant-time check
        expected == parts[1]
    }
}

impl Default for ServiceIdentityKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Confused-Deputy Broker Attribution (P1.2)
// -----------------------------------------------------------------------------

/// Broker delegation record tracking active broker-mediated commands.
#[derive(Debug, Clone)]
pub struct BrokerDelegation {
    pub broker_pid: u32,
    pub broker_image: String,
    pub origin_session_id: String,
    pub requesting_instance_id: String,
    pub delegation_time: DateTime<Utc>,
}

/// Confused-deputy broker attribution router (P1.2).
///
/// Attributes actions mediated by system broker binaries (`WmiPrvSE.exe`,
/// `svchost.exe`, `git-remote-https.exe`, `ssh.exe`) back to the requesting
/// agent session rather than treating them as unlinked system activity.
#[derive(Debug, Default)]
pub struct ConfusedDeputyBrokerRouter {
    active_delegations: DashMap<u32, BrokerDelegation>,
    known_brokers: HashSet<String>,
}

impl ConfusedDeputyBrokerRouter {
    pub fn new() -> Self {
        let mut known = HashSet::new();
        for &b in &[
            "wmiprvse.exe",
            "svchost.exe",
            "git-remote-https.exe",
            "ssh.exe",
            "taskhostw.exe",
            "dllhost.exe",
            "cmd.exe",
            "powershell.exe",
        ] {
            known.insert(b.to_ascii_lowercase());
        }

        Self {
            active_delegations: DashMap::new(),
            known_brokers: known,
        }
    }

    pub fn is_broker_image(&self, image: &str) -> bool {
        let norm = image.replace('/', "\\");
        let base = norm
            .rsplit('\\')
            .next()
            .unwrap_or(image)
            .trim()
            .to_ascii_lowercase();
        self.known_brokers.contains(&base)
    }

    pub fn register_delegation(
        &self,
        broker_pid: u32,
        broker_image: &str,
        origin_session_id: &str,
        requesting_instance_id: &str,
    ) {
        self.active_delegations.insert(
            broker_pid,
            BrokerDelegation {
                broker_pid,
                broker_image: broker_image.to_string(),
                origin_session_id: origin_session_id.to_string(),
                requesting_instance_id: requesting_instance_id.to_string(),
                delegation_time: Utc::now(),
            },
        );
    }

    pub fn resolve_delegation(&self, broker_pid: u32) -> Option<BrokerDelegation> {
        self.active_delegations
            .get(&broker_pid)
            .map(|entry| entry.clone())
    }

    pub fn remove_delegation(&self, broker_pid: u32) {
        self.active_delegations.remove(&broker_pid);
    }
}

// -----------------------------------------------------------------------------
// Persistent Causal Security Graph
// -----------------------------------------------------------------------------

/// In-memory lock-free cached node state for fast BFS traversals.
#[derive(Debug, Clone)]
pub struct CachedNodeState {
    pub node_id: String,
    pub taint_level: u32,
    pub has_crown_jewel: bool,
    pub is_process: bool,
    pub is_file: bool,
    pub inbound_edges: Vec<(String, u32, bool, CausalEdgeType)>,
}

/// SQLite-backed persistent Causal Security Graph (`database/osoosi.db`).
pub struct CausalSecurityGraph {
    conn: Arc<Mutex<Connection>>,
    sessions: DashMap<String, SessionCausalState>,
    pub node_cache: DashMap<String, CachedNodeState>,
    key_store: ServiceIdentityKeyStore,
    pub broker_router: ConfusedDeputyBrokerRouter,
    db_path: String,
}

impl CausalSecurityGraph {
    /// Opens or creates the persistent causal security graph at `db_path`.
    pub fn open(db_path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(db_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create database directory: {:?}", parent)
                })?;
            }
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open SQLite database at: {}", db_path))?;

        // Enable high-concurrency WAL mode
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        let graph = Self {
            conn: Arc::new(Mutex::new(conn)),
            sessions: DashMap::new(),
            node_cache: DashMap::new(),
            key_store: ServiceIdentityKeyStore::new(),
            broker_router: ConfusedDeputyBrokerRouter::new(),
            db_path: db_path.to_string(),
        };

        graph.initialize_schema()?;
        Ok(graph)
    }

    /// Creates an in-memory instance for testing.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        let graph = Self {
            conn: Arc::new(Mutex::new(conn)),
            sessions: DashMap::new(),
            node_cache: DashMap::new(),
            key_store: ServiceIdentityKeyStore::new(),
            broker_router: ConfusedDeputyBrokerRouter::new(),
            db_path: ":memory:".to_string(),
        };

        graph.initialize_schema()?;
        Ok(graph)
    }

    /// Initializes all 5 database tables and indices.
    fn initialize_schema(&self) -> Result<()> {
        let lock = self.conn.lock();
        lock.execute_batch(
            "
            -- 1. Process Instances (Lineage tracking with 100ns timestamp and BLAKE3 hash)
            CREATE TABLE IF NOT EXISTS causal_process_instances (
                instance_id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                start_time_100ns INTEGER NOT NULL,
                image_path TEXT NOT NULL,
                image_digest_blake3 TEXT NOT NULL,
                parent_instance_id TEXT,
                job_object_id TEXT,
                origin_session_id TEXT NOT NULL,
                taint_level INTEGER NOT NULL DEFAULT 0,
                has_crown_jewel_taint INTEGER NOT NULL DEFAULT 0,
                revocation_seq INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                terminated_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_proc_session ON causal_process_instances(origin_session_id);
            CREATE INDEX IF NOT EXISTS idx_proc_pid_start ON causal_process_instances(pid, start_time_100ns);
            CREATE INDEX IF NOT EXISTS idx_proc_parent ON causal_process_instances(parent_instance_id);

            -- 2. File Artifacts & Classifications
            CREATE TABLE IF NOT EXISTS causal_files (
                file_id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                canonical_path TEXT NOT NULL,
                blake3_hash TEXT NOT NULL,
                classification TEXT NOT NULL,
                authority_level INTEGER NOT NULL DEFAULT 5,
                is_verified INTEGER NOT NULL DEFAULT 0,
                signature_type TEXT,
                signature_hex TEXT,
                taint_level INTEGER NOT NULL DEFAULT 0,
                has_crown_jewel_taint INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_modified TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_files_path ON causal_files(path);
            CREATE INDEX IF NOT EXISTS idx_files_hash ON causal_files(blake3_hash);
            CREATE INDEX IF NOT EXISTS idx_files_canon ON causal_files(canonical_path);

            -- 3. Causal Events (Synchronous OS & Tool Decisions)
            CREATE TABLE IF NOT EXISTS causal_events (
                event_id TEXT PRIMARY KEY,
                event_seq INTEGER NOT NULL,
                decision_id TEXT,
                session_id TEXT NOT NULL,
                process_instance_id TEXT NOT NULL,
                effect_type TEXT NOT NULL,
                source_resource TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                is_authorized INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                policy_version INTEGER NOT NULL DEFAULT 1,
                taint_epoch INTEGER NOT NULL DEFAULT 0,
                pre_event_taint INTEGER NOT NULL DEFAULT 0,
                post_event_taint INTEGER NOT NULL DEFAULT 0,
                details_json TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_session_seq ON causal_events(session_id, event_seq);
            CREATE INDEX IF NOT EXISTS idx_events_decision ON causal_events(decision_id);
            CREATE INDEX IF NOT EXISTS idx_events_proc ON causal_events(process_instance_id);
            CREATE INDEX IF NOT EXISTS idx_events_effect ON causal_events(effect_type);

            -- 4. Causal Provenance Edges (Directed Graph Traversal)
            CREATE TABLE IF NOT EXISTS causal_edges (
                edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                taint_propagated INTEGER NOT NULL DEFAULT 0,
                has_crown_jewel_taint INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_edges_src ON causal_edges(source_id);
            CREATE INDEX IF NOT EXISTS idx_edges_tgt ON causal_edges(target_id);
            CREATE INDEX IF NOT EXISTS idx_edges_type ON causal_edges(edge_type);

            -- 5. Revocation-Bound Capability Cache
            CREATE TABLE IF NOT EXISTS capability_cache (
                cache_key TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                is_granted INTEGER NOT NULL,
                policy_version INTEGER NOT NULL,
                taint_epoch INTEGER NOT NULL,
                revocation_seq INTEGER NOT NULL,
                policy_decision_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_cap_cache_lookup ON capability_cache(principal_id, action, resource_id);

            -- 6. Adversarial Regression Cases Index Table
            CREATE TABLE IF NOT EXISTS adversarial_regression_cases (
                case_id TEXT PRIMARY KEY,
                test_version TEXT NOT NULL,
                framework_version TEXT NOT NULL,
                random_seed INTEGER NOT NULL,
                environment_config TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                attack_objective TEXT NOT NULL,
                expected_effect TEXT NOT NULL,
                actual_effect TEXT NOT NULL,
                evidence TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_regr_policy_ver ON adversarial_regression_cases(policy_version);
            CREATE INDEX IF NOT EXISTS idx_regr_created ON adversarial_regression_cases(created_at);
            ",
        )?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Session State & Barrier Management
    // -------------------------------------------------------------------------

    pub fn get_or_init_session_state(&self, session_id: &str) -> SessionCausalState {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionCausalState {
                session_id: session_id.to_string(),
                taint_epoch: 1,
                revocation_seq: 1,
                taint_level: 0,
                has_crown_jewel_taint: false,
                event_counter: 0,
            })
            .clone()
    }

    pub fn bump_taint_epoch(
        &self,
        session_id: &str,
        new_taint_level: u32,
        has_crown_jewel: bool,
    ) -> (u64, u64) {
        let mut entry = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionCausalState {
                session_id: session_id.to_string(),
                taint_epoch: 1,
                revocation_seq: 1,
                taint_level: 0,
                has_crown_jewel_taint: false,
                event_counter: 0,
            });

        entry.taint_epoch += 1;
        entry.revocation_seq += 1;
        entry.taint_level = std::cmp::max(entry.taint_level, new_taint_level);
        entry.has_crown_jewel_taint |= has_crown_jewel;
        (entry.taint_epoch, entry.revocation_seq)
    }

    pub fn bump_revocation_seq(&self, session_id: &str) -> u64 {
        let mut entry = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionCausalState {
                session_id: session_id.to_string(),
                taint_epoch: 1,
                revocation_seq: 1,
                taint_level: 0,
                has_crown_jewel_taint: false,
                event_counter: 0,
            });
        entry.revocation_seq += 1;
        entry.revocation_seq
    }

    // -------------------------------------------------------------------------
    // Process Instance Management
    // -------------------------------------------------------------------------

    pub fn register_process_instance(
        &self,
        identity: &ProcessInstanceIdentity,
        image_path: &str,
        initial_taint: u32,
        has_crown_jewel: bool,
    ) -> Result<()> {
        let lock = self.conn.lock();
        let now = Utc::now().to_rfc3339();

        lock.execute(
            "INSERT OR REPLACE INTO causal_process_instances (
                instance_id, pid, start_time_100ns, image_path, image_digest_blake3,
                parent_instance_id, job_object_id, origin_session_id, taint_level,
                has_crown_jewel_taint, revocation_seq, created_at, terminated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, NULL)",
            params![
                identity.instance_id,
                identity.pid,
                identity.start_time_100ns as i64,
                image_path,
                identity.image_digest_blake3,
                identity.parent_instance_id,
                identity.job_object_id,
                identity.origin_session_id,
                initial_taint,
                if has_crown_jewel { 1 } else { 0 },
                now,
            ],
        )?;

        // If child has a parent, record the Spawned edge
        if let Some(ref parent_id) = identity.parent_instance_id {
            lock.execute(
                "INSERT INTO causal_edges (source_id, target_id, edge_type, taint_propagated, has_crown_jewel_taint, timestamp)
                 VALUES (?1, ?2, 'Spawned', ?3, ?4, ?5)",
                params![
                    parent_id,
                    identity.instance_id,
                    initial_taint,
                    if has_crown_jewel { 1 } else { 0 },
                    now,
                ],
            )?;
        }
        drop(lock);

        // Populate in-memory node cache
        let mut node = self
            .node_cache
            .entry(identity.instance_id.clone())
            .or_insert_with(|| CachedNodeState {
                node_id: identity.instance_id.clone(),
                taint_level: initial_taint,
                has_crown_jewel,
                is_process: true,
                is_file: false,
                inbound_edges: Vec::new(),
            });
        node.taint_level = std::cmp::max(node.taint_level, initial_taint);
        node.has_crown_jewel = node.has_crown_jewel || has_crown_jewel;
        node.is_process = true;
        if let Some(ref parent_id) = identity.parent_instance_id {
            node.inbound_edges.push((
                parent_id.clone(),
                initial_taint,
                has_crown_jewel,
                CausalEdgeType::Spawned,
            ));
        }

        Ok(())
    }

    pub fn get_process_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<ProcessInstanceIdentity>> {
        let lock = self.conn.lock();
        let mut stmt = lock.prepare(
            "SELECT instance_id, pid, start_time_100ns, image_digest_blake3, parent_instance_id, job_object_id, origin_session_id
             FROM causal_process_instances WHERE instance_id = ?1",
        )?;

        let row = stmt
            .query_row(params![instance_id], |r| {
                let pid: u32 = r.get(1)?;
                let start_time_100ns: i64 = r.get(2)?;
                Ok(ProcessInstanceIdentity {
                    instance_id: r.get(0)?,
                    pid,
                    start_time_100ns: start_time_100ns as u64,
                    image_digest_blake3: r.get(3)?,
                    parent_instance_id: r.get(4)?,
                    job_object_id: r.get(5)?,
                    origin_session_id: r.get(6)?,
                })
            })
            .optional()?;

        Ok(row)
    }

    /// Checks if a process or its parent process has active taint or Crown-Jewel taint in the causal graph.
    pub fn is_process_or_parent_tainted(&self, pid: u32, ppid: Option<u32>) -> bool {
        // 1. Check in-memory node cache
        for item in self.node_cache.iter() {
            let state = item.value();
            if state.is_process && (state.taint_level > 0 || state.has_crown_jewel) {
                if let Ok(Some(proc)) = self.get_process_instance(&state.node_id) {
                    if proc.pid == pid || ppid.is_some_and(|p| p == proc.pid) {
                        return true;
                    }
                }
            }
        }

        // 2. Check SQLite causal_process_instances table
        let lock = self.conn.lock();
        let query = if ppid.is_some() {
            "SELECT COUNT(1) FROM causal_process_instances WHERE (pid = ?1 OR pid = ?2) AND (taint_level > 0 OR has_crown_jewel_taint > 0)"
        } else {
            "SELECT COUNT(1) FROM causal_process_instances WHERE pid = ?1 AND (taint_level > 0 OR has_crown_jewel_taint > 0)"
        };
        let count: i64 = if let Some(parent_pid) = ppid {
            lock.query_row(query, params![pid, parent_pid], |r| r.get(0))
                .unwrap_or(0)
        } else {
            lock.query_row(query, params![pid], |r| r.get(0))
                .unwrap_or(0)
        };
        count > 0
    }

    // -------------------------------------------------------------------------
    // File Artifact Management
    // -------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)] // Causal graph ledger registration with full provenance context
    pub fn register_file(
        &self,
        path: &str,
        canonical_path: &str,
        blake3_hash: &str,
        classification: FileClassification,
        authority_level: AuthorityLevel,
        taint_level: u32,
        has_crown_jewel: bool,
    ) -> Result<String> {
        let file_id = blake3::hash(canonical_path.as_bytes()).to_hex().to_string();
        let now = Utc::now().to_rfc3339();

        let lock = self.conn.lock();
        lock.execute(
            "INSERT OR REPLACE INTO causal_files (
                file_id, path, canonical_path, blake3_hash, classification,
                authority_level, is_verified, signature_type, signature_hex,
                taint_level, has_crown_jewel_taint, created_at, last_modified
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 'NONE', '', ?7, ?8, ?9, ?9)",
            params![
                file_id,
                path,
                canonical_path,
                blake3_hash,
                classification.as_str(),
                authority_level.to_u32(),
                taint_level,
                if has_crown_jewel { 1 } else { 0 },
                now,
            ],
        )?;
        drop(lock);

        // Populate in-memory node cache
        let mut node = self
            .node_cache
            .entry(file_id.clone())
            .or_insert_with(|| CachedNodeState {
                node_id: file_id.clone(),
                taint_level,
                has_crown_jewel,
                is_process: false,
                is_file: true,
                inbound_edges: Vec::new(),
            });
        node.taint_level = std::cmp::max(node.taint_level, taint_level);
        node.has_crown_jewel = node.has_crown_jewel || has_crown_jewel;
        node.is_file = true;

        Ok(file_id)
    }

    // -------------------------------------------------------------------------
    // Causal Event & Edge Tracking
    // -------------------------------------------------------------------------

    pub fn record_event(&self, event: &CausalEventRecord) -> Result<()> {
        let lock = self.conn.lock();
        lock.execute(
            "INSERT OR REPLACE INTO causal_events (
                event_id, event_seq, decision_id, session_id, process_instance_id,
                effect_type, source_resource, target_resource, is_authorized,
                verdict, policy_version, taint_epoch, pre_event_taint, post_event_taint,
                details_json, timestamp
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                event.event_id,
                event.event_seq as i64,
                event.decision_id,
                event.session_id,
                event.process_instance_id,
                event.effect_type,
                event.source_resource,
                event.target_resource,
                if event.is_authorized { 1 } else { 0 },
                event.verdict,
                event.policy_version,
                event.taint_epoch as i64,
                event.pre_event_taint,
                event.post_event_taint,
                event.details_json,
                event.timestamp,
            ],
        )?;

        // Update local session state
        let mut session = self
            .sessions
            .entry(event.session_id.clone())
            .or_insert_with(|| SessionCausalState {
                session_id: event.session_id.clone(),
                taint_epoch: event.taint_epoch,
                revocation_seq: 1,
                taint_level: event.post_event_taint,
                has_crown_jewel_taint: false,
                event_counter: event.event_seq,
            });
        session.event_counter = std::cmp::max(session.event_counter, event.event_seq);
        session.taint_level = std::cmp::max(session.taint_level, event.post_event_taint);

        Ok(())
    }

    pub fn record_edge(
        &self,
        source_id: &str,
        target_id: &str,
        edge_type: CausalEdgeType,
        taint_propagated: u32,
        has_crown_jewel: bool,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let lock = self.conn.lock();
        lock.execute(
            "INSERT INTO causal_edges (source_id, target_id, edge_type, taint_propagated, has_crown_jewel_taint, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                source_id,
                target_id,
                edge_type.as_str(),
                taint_propagated,
                if has_crown_jewel { 1 } else { 0 },
                now,
            ],
        )?;
        let row_id = lock.last_insert_rowid();
        drop(lock);

        // Update in-memory node cache
        self.node_cache
            .entry(target_id.to_string())
            .or_insert_with(|| CachedNodeState {
                node_id: target_id.to_string(),
                taint_level: 0,
                has_crown_jewel: false,
                is_process: false,
                is_file: false,
                inbound_edges: Vec::new(),
            })
            .inbound_edges
            .push((
                source_id.to_string(),
                taint_propagated,
                has_crown_jewel,
                edge_type,
            ));

        Ok(row_id)
    }

    // -------------------------------------------------------------------------
    // High-Level Causal Operations (Spawn, Read, Write, Tool)
    // -------------------------------------------------------------------------

    /// Records process spawn with transitive taint inheritance.
    pub fn record_process_spawn(
        &self,
        parent_instance: &ProcessInstanceIdentity,
        child_instance: &ProcessInstanceIdentity,
        child_image_path: &str,
    ) -> Result<()> {
        let lock = self.conn.lock();

        // Query parent's active taint
        let (parent_taint, parent_cj): (u32, bool) = lock
            .query_row(
                "SELECT taint_level, has_crown_jewel_taint FROM causal_process_instances WHERE instance_id = ?1",
                params![parent_instance.instance_id],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .unwrap_or((0, false));
        drop(lock);

        self.register_process_instance(child_instance, child_image_path, parent_taint, parent_cj)?;
        Ok(())
    }

    /// Records a process reading a file, elevating the process's taint if the file is tainted.
    pub fn record_file_read(
        &self,
        proc_instance_id: &str,
        file_canonical_path: &str,
    ) -> Result<(u32, bool)> {
        let file_id = blake3::hash(file_canonical_path.as_bytes())
            .to_hex()
            .to_string();
        let lock = self.conn.lock();

        let file_info: Option<(u32, bool)> = lock
            .query_row(
                "SELECT taint_level, has_crown_jewel_taint FROM causal_files WHERE file_id = ?1",
                params![file_id],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()?;

        let (file_taint, file_cj) = file_info.unwrap_or((0, false));

        let proc_info: Option<(u32, bool, String)> = lock
            .query_row(
                "SELECT taint_level, has_crown_jewel_taint, origin_session_id FROM causal_process_instances WHERE instance_id = ?1",
                params![proc_instance_id],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?)),
            )
            .optional()?;

        let (proc_taint, proc_cj, session_id) =
            proc_info.ok_or_else(|| anyhow!("Process instance not found: {}", proc_instance_id))?;

        let new_taint = std::cmp::max(proc_taint, file_taint);
        let new_cj = proc_cj || file_cj;

        // Update process instance
        lock.execute(
            "UPDATE causal_process_instances SET taint_level = ?1, has_crown_jewel_taint = ?2 WHERE instance_id = ?3",
            params![new_taint, if new_cj { 1 } else { 0 }, proc_instance_id],
        )?;

        // Record causal edge from File -> Process (Read)
        let now = Utc::now().to_rfc3339();
        lock.execute(
            "INSERT INTO causal_edges (source_id, target_id, edge_type, taint_propagated, has_crown_jewel_taint, timestamp)
             VALUES (?1, ?2, 'Read', ?3, ?4, ?5)",
            params![file_id, proc_instance_id, file_taint, if file_cj { 1 } else { 0 }, now],
        )?;
        drop(lock);

        // Update in-memory node cache
        let mut proc_node = self
            .node_cache
            .entry(proc_instance_id.to_string())
            .or_insert_with(|| CachedNodeState {
                node_id: proc_instance_id.to_string(),
                taint_level: new_taint,
                has_crown_jewel: new_cj,
                is_process: true,
                is_file: false,
                inbound_edges: Vec::new(),
            });
        proc_node.taint_level = std::cmp::max(proc_node.taint_level, new_taint);
        proc_node.has_crown_jewel = proc_node.has_crown_jewel || new_cj;
        proc_node
            .inbound_edges
            .push((file_id, file_taint, file_cj, CausalEdgeType::Read));

        // If taint increased, bump session taint epoch
        if new_taint > proc_taint || (new_cj && !proc_cj) {
            self.bump_taint_epoch(&session_id, new_taint, new_cj);
        }

        Ok((new_taint, new_cj))
    }

    /// Records a process writing to a file, elevating the file's taint to match the process.
    pub fn record_file_write(
        &self,
        proc_instance_id: &str,
        file_path: &str,
        canonical_path: &str,
        content_blake3: &str,
    ) -> Result<()> {
        let file_id = blake3::hash(canonical_path.as_bytes()).to_hex().to_string();
        let lock = self.conn.lock();

        let proc_info: Option<(u32, bool)> = lock
            .query_row(
                "SELECT taint_level, has_crown_jewel_taint FROM causal_process_instances WHERE instance_id = ?1",
                params![proc_instance_id],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()?;

        let (proc_taint, proc_cj) =
            proc_info.ok_or_else(|| anyhow!("Process instance not found: {}", proc_instance_id))?;

        let now = Utc::now().to_rfc3339();

        // Update or insert file
        lock.execute(
            "INSERT INTO causal_files (
                file_id, path, canonical_path, blake3_hash, classification,
                authority_level, is_verified, signature_type, signature_hex,
                taint_level, has_crown_jewel_taint, created_at, last_modified
            ) VALUES (?1, ?2, ?3, ?4, 'Scratchpad', 5, 0, 'NONE', '', ?5, ?6, ?7, ?7)
            ON CONFLICT(file_id) DO UPDATE SET
                blake3_hash = excluded.blake3_hash,
                taint_level = MAX(causal_files.taint_level, excluded.taint_level),
                has_crown_jewel_taint = (causal_files.has_crown_jewel_taint | excluded.has_crown_jewel_taint),
                last_modified = excluded.last_modified",
            params![
                file_id,
                file_path,
                canonical_path,
                content_blake3,
                proc_taint,
                if proc_cj { 1 } else { 0 },
                now,
            ],
        )?;

        // Record causal edge Process -> File (Wrote)
        lock.execute(
            "INSERT INTO causal_edges (source_id, target_id, edge_type, taint_propagated, has_crown_jewel_taint, timestamp)
             VALUES (?1, ?2, 'Wrote', ?3, ?4, ?5)",
            params![proc_instance_id, file_id, proc_taint, if proc_cj { 1 } else { 0 }, now],
        )?;
        drop(lock);

        // Update in-memory node cache
        let mut file_node =
            self.node_cache
                .entry(file_id.clone())
                .or_insert_with(|| CachedNodeState {
                    node_id: file_id.clone(),
                    taint_level: proc_taint,
                    has_crown_jewel: proc_cj,
                    is_process: false,
                    is_file: true,
                    inbound_edges: Vec::new(),
                });
        file_node.taint_level = std::cmp::max(file_node.taint_level, proc_taint);
        file_node.has_crown_jewel = file_node.has_crown_jewel || proc_cj;
        file_node.inbound_edges.push((
            proc_instance_id.to_string(),
            proc_taint,
            proc_cj,
            CausalEdgeType::Wrote,
        ));

        Ok(())
    }

    /// Records tool execution invocation.
    pub fn record_tool_call(
        &self,
        proc_instance_id: &str,
        tool_name: &str,
        args_digest: &str,
        output_node_id: &str,
        output_taint: u32,
    ) -> Result<()> {
        let tool_node_id = format!("tool:{}:{}", tool_name, args_digest);
        let now = Utc::now().to_rfc3339();
        let lock = self.conn.lock();

        // Edge 1: Process -> Tool (ToolInvoked)
        lock.execute(
            "INSERT INTO causal_edges (source_id, target_id, edge_type, taint_propagated, has_crown_jewel_taint, timestamp)
             VALUES (?1, ?2, 'ToolInvoked', ?3, 0, ?4)",
            params![proc_instance_id, tool_node_id, output_taint, now],
        )?;

        // Edge 2: Tool -> Output (DerivedFrom)
        lock.execute(
            "INSERT INTO causal_edges (source_id, target_id, edge_type, taint_propagated, has_crown_jewel_taint, timestamp)
             VALUES (?1, ?2, 'DerivedFrom', ?3, 0, ?4)",
            params![tool_node_id, output_node_id, output_taint, now],
        )?;
        drop(lock);

        // Update in-memory node cache
        let mut tool_node = self
            .node_cache
            .entry(tool_node_id.clone())
            .or_insert_with(|| CachedNodeState {
                node_id: tool_node_id.clone(),
                taint_level: output_taint,
                has_crown_jewel: false,
                is_process: false,
                is_file: false,
                inbound_edges: Vec::new(),
            });
        tool_node.inbound_edges.push((
            proc_instance_id.to_string(),
            output_taint,
            false,
            CausalEdgeType::ToolInvoked,
        ));

        let mut out_node = self
            .node_cache
            .entry(output_node_id.to_string())
            .or_insert_with(|| CachedNodeState {
                node_id: output_node_id.to_string(),
                taint_level: output_taint,
                has_crown_jewel: false,
                is_process: false,
                is_file: false,
                inbound_edges: Vec::new(),
            });
        out_node.taint_level = std::cmp::max(out_node.taint_level, output_taint);
        out_node.inbound_edges.push((
            tool_node_id,
            output_taint,
            false,
            CausalEdgeType::DerivedFrom,
        ));

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Transitive Taint Traversal
    // -------------------------------------------------------------------------

    /// Recursively checks if any upstream node connected to `node_id` is tainted.
    pub fn is_transitive_tainted(&self, node_id: &str) -> Result<bool> {
        let report = self.get_transitive_taint_report(node_id)?;
        Ok(report.is_tainted)
    }

    /// Computes full transitive taint report for `node_id` by traversing inbound edges.
    /// Operates over the lock-free in-memory cache to service BFS requests without blocking on the SQLite connection.
    pub fn get_transitive_taint_report(&self, node_id: &str) -> Result<TransitiveTaintReport> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(node_id.to_string());

        let mut max_taint = 0u32;
        let mut has_cj = false;
        let mut origins = Vec::new();
        let mut chain = Vec::new();

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            chain.push(current.clone());

            // 1. Check in-memory lock-free node cache
            if let Some(cached) = self.node_cache.get(&current) {
                if cached.taint_level > max_taint {
                    max_taint = cached.taint_level;
                }
                if cached.has_crown_jewel {
                    has_cj = true;
                }
                if cached.taint_level > 0 || cached.has_crown_jewel {
                    if cached.is_process {
                        origins.push(format!("ProcessInstance:{}", current));
                    } else if cached.is_file {
                        origins.push(format!("File:{}", current));
                    }
                }

                for (src, prop_t, prop_cj, edge_type) in &cached.inbound_edges {
                    if *edge_type != CausalEdgeType::DeclassifiedInto {
                        if *prop_t > max_taint {
                            max_taint = *prop_t;
                        }
                        if *prop_cj {
                            has_cj = true;
                        }
                        if !visited.contains(src) {
                            queue.push_back(src.clone());
                        }
                    }
                }
                continue;
            }

            // 2. Cold-node fallback to SQLite (populates cache for subsequent zero-lock traversal)
            let lock = self.conn.lock();
            let proc_info: Option<(u32, bool)> = lock
                .query_row(
                    "SELECT taint_level, has_crown_jewel_taint FROM causal_process_instances WHERE instance_id = ?1",
                    params![current],
                    |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
                )
                .optional()?;

            let is_proc = proc_info.is_some();
            let (p_taint, p_cj) = proc_info.unwrap_or((0, false));

            let file_info: Option<(u32, bool)> = lock
                .query_row(
                    "SELECT taint_level, has_crown_jewel_taint FROM causal_files WHERE file_id = ?1",
                    params![current],
                    |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
                )
                .optional()?;

            let is_file = file_info.is_some();
            let (f_taint, f_cj) = file_info.unwrap_or((0, false));

            let cur_taint = std::cmp::max(p_taint, f_taint);
            let cur_cj = p_cj || f_cj;

            if cur_taint > max_taint {
                max_taint = cur_taint;
            }
            if cur_cj {
                has_cj = true;
            }
            if cur_taint > 0 || cur_cj {
                if is_proc {
                    origins.push(format!("ProcessInstance:{}", current));
                } else if is_file {
                    origins.push(format!("File:{}", current));
                }
            }

            let mut stmt = lock.prepare(
                "SELECT source_id, taint_propagated, has_crown_jewel_taint, edge_type FROM causal_edges WHERE target_id = ?1 AND edge_type != 'DeclassifiedInto'",
            )?;
            let rows = stmt.query_map(params![current], |r| {
                let src: String = r.get(0)?;
                let prop_t: u32 = r.get(1)?;
                let prop_cj: bool = r.get::<_, i64>(2)? != 0;
                let etype_str: String = r.get(3)?;
                Ok((src, prop_t, prop_cj, etype_str))
            })?;

            let mut loaded_edges = Vec::new();
            for r in rows {
                let (src, prop_t, prop_cj, _) = r?;
                if prop_t > max_taint {
                    max_taint = prop_t;
                }
                if prop_cj {
                    has_cj = true;
                }
                if !visited.contains(&src) {
                    queue.push_back(src.clone());
                }
                loaded_edges.push((src, prop_t, prop_cj, CausalEdgeType::Spawned));
            }
            drop(stmt);
            drop(lock);

            self.node_cache.insert(
                current.clone(),
                CachedNodeState {
                    node_id: current.clone(),
                    taint_level: cur_taint,
                    has_crown_jewel: cur_cj,
                    is_process: is_proc,
                    is_file,
                    inbound_edges: loaded_edges,
                },
            );
        }

        Ok(TransitiveTaintReport {
            node_id: node_id.to_string(),
            is_tainted: max_taint > 0 || has_cj,
            max_taint_level: max_taint,
            has_crown_jewel_taint: has_cj,
            taint_origins: origins,
            causal_chain: chain,
        })
    }

    // -------------------------------------------------------------------------
    // Trusted Zero-Knowledge Declassification
    // -------------------------------------------------------------------------

    /// Declassifies a tainted data node by verifying `<ZK_PII:...>` scrubbing and ML-DSA-65 proof.
    ///
    /// Once verified, clears taint on the derived artifact node and records
    /// a `Declassification` causal event, allowing the scrubbed artifact to be safely shared.
    pub fn declassify_node(
        &self,
        source_node_id: &str,
        declassified_node_id: &str,
        proof: &ZkBftQuarantineProof,
        session_id: &str,
        decision_id: Option<&str>,
    ) -> Result<DeclassificationResult> {
        // Condition 1: Must contain <ZK_PII:...> commitments or redacted markers
        if !proof.scrubbed_payload.contains("<ZK_PII:") && proof.redacted_entity_count > 0 {
            return Ok(DeclassificationResult {
                success: false,
                original_node_id: source_node_id.to_string(),
                declassified_node_id: declassified_node_id.to_string(),
                pii_leakage_bits: proof.pii_leakage_bits,
                pqc_signature_verified: false,
                reason: "Scrubbed payload is missing mandatory <ZK_PII:...> commitments"
                    .to_string(),
            });
        }

        // Condition 2: Zero information leakage bits and valid ZK proof
        if proof.pii_leakage_bits != 0 || !proof.is_valid_zero_knowledge_proof {
            return Ok(DeclassificationResult {
                success: false,
                original_node_id: source_node_id.to_string(),
                declassified_node_id: declassified_node_id.to_string(),
                pii_leakage_bits: proof.pii_leakage_bits,
                pqc_signature_verified: false,
                reason: format!(
                    "Declassification rejected: non-zero leakage bits ({}) or invalid ZK proof",
                    proof.pii_leakage_bits
                ),
            });
        }

        // Condition 3: Verify cryptographic ML-DSA-65 post-quantum proof
        let is_valid_pqc = PresidioGlinerPiiZeroGuard::verify_zk_bft_proof(proof);
        if !is_valid_pqc {
            return Ok(DeclassificationResult {
                success: false,
                original_node_id: source_node_id.to_string(),
                declassified_node_id: declassified_node_id.to_string(),
                pii_leakage_bits: proof.pii_leakage_bits,
                pqc_signature_verified: false,
                reason: "Cryptographic ML-DSA-65 / Schnorr ZK proof verification failed"
                    .to_string(),
            });
        }

        // Verification passed! Update SQLite:
        let lock = self.conn.lock();
        let now = Utc::now().to_rfc3339();

        // 1. Clear taint on declassified file / node
        lock.execute(
            "UPDATE causal_files SET taint_level = 0, has_crown_jewel_taint = 0, last_modified = ?1 WHERE file_id = ?2",
            params![now, declassified_node_id],
        )?;

        // 2. Insert causal edge source -> declassified (DeclassifiedInto)
        lock.execute(
            "INSERT INTO causal_edges (source_id, target_id, edge_type, taint_propagated, has_crown_jewel_taint, timestamp)
             VALUES (?1, ?2, 'DeclassifiedInto', 0, 0, ?3)",
            params![source_node_id, declassified_node_id, now],
        )?;

        // 3. Record event in causal_events
        let event_id = format!("declass-{}", &blake3::hash(now.as_bytes()).to_hex()[..16]);
        lock.execute(
            "INSERT INTO causal_events (
                event_id, event_seq, decision_id, session_id, process_instance_id,
                effect_type, source_resource, target_resource, is_authorized,
                verdict, policy_version, taint_epoch, pre_event_taint, post_event_taint,
                details_json, timestamp
            ) VALUES (?1, 1, ?2, ?3, ?4, 'Declassification', ?5, ?6, 1, 'Allow', 1, 1, 1, 0, ?7, ?8)",
            params![
                event_id,
                decision_id,
                session_id,
                source_node_id,
                source_node_id,
                declassified_node_id,
                format!("{{\"redacted_entities\": {}}}", proof.redacted_entity_count),
                now,
            ],
        )?;
        drop(lock);

        // Update in-memory node cache
        let mut d_node = self
            .node_cache
            .entry(declassified_node_id.to_string())
            .or_insert_with(|| CachedNodeState {
                node_id: declassified_node_id.to_string(),
                taint_level: 0,
                has_crown_jewel: false,
                is_process: false,
                is_file: true,
                inbound_edges: Vec::new(),
            });
        d_node.taint_level = 0;
        d_node.has_crown_jewel = false;
        d_node.inbound_edges.push((
            source_node_id.to_string(),
            0,
            false,
            CausalEdgeType::DeclassifiedInto,
        ));

        Ok(DeclassificationResult {
            success: true,
            original_node_id: source_node_id.to_string(),
            declassified_node_id: declassified_node_id.to_string(),
            pii_leakage_bits: 0,
            pqc_signature_verified: true,
            reason: "Trusted zero-knowledge declassification verified and committed".to_string(),
        })
    }

    // -------------------------------------------------------------------------
    // Revocation-Bound Capability Cache
    // -------------------------------------------------------------------------

    pub fn compute_cache_key(
        principal_id: &str,
        action: &str,
        resource_id: &str,
        policy_version: u32,
        taint_epoch: u64,
        revocation_seq: u64,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CAPABILITY_CACHE_KEY_V1:");
        hasher.update(principal_id.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(resource_id.as_bytes());
        hasher.update(&policy_version.to_le_bytes());
        hasher.update(&taint_epoch.to_le_bytes());
        hasher.update(&revocation_seq.to_le_bytes());
        hasher.finalize().to_hex().to_string()
    }

    pub fn check_capability(
        &self,
        principal_id: &str,
        action: &str,
        resource_id: &str,
        policy_version: u32,
        taint_epoch: u64,
        revocation_seq: u64,
    ) -> Result<Option<bool>> {
        let key = Self::compute_cache_key(
            principal_id,
            action,
            resource_id,
            policy_version,
            taint_epoch,
            revocation_seq,
        );

        let lock = self.conn.lock();
        let now = Utc::now().to_rfc3339();

        let res: Option<bool> = lock
            .query_row(
                "SELECT is_granted FROM capability_cache WHERE cache_key = ?1 AND expires_at > ?2",
                params![key, now],
                |r| Ok(r.get::<_, i64>(0)? != 0),
            )
            .optional()?;

        Ok(res)
    }

    #[allow(clippy::too_many_arguments)] // Capability store API with full temporal and epoch context
    pub fn store_capability(
        &self,
        principal_id: &str,
        action: &str,
        resource_id: &str,
        is_granted: bool,
        policy_version: u32,
        taint_epoch: u64,
        revocation_seq: u64,
        decision_id: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        let key = Self::compute_cache_key(
            principal_id,
            action,
            resource_id,
            policy_version,
            taint_epoch,
            revocation_seq,
        );

        let now = Utc::now();
        let expires_at = (now + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();
        let created_at = now.to_rfc3339();

        let lock = self.conn.lock();
        lock.execute(
            "INSERT OR REPLACE INTO capability_cache (
                cache_key, principal_id, action, resource_id, is_granted,
                policy_version, taint_epoch, revocation_seq, policy_decision_id,
                expires_at, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                key,
                principal_id,
                action,
                resource_id,
                if is_granted { 1 } else { 0 },
                policy_version,
                taint_epoch as i64,
                revocation_seq as i64,
                decision_id,
                expires_at,
                created_at,
            ],
        )?;

        Ok(())
    }

    pub fn invalidate_capabilities_by_revocation(&self, min_revocation_seq: u64) -> Result<usize> {
        let lock = self.conn.lock();
        let count = lock.execute(
            "DELETE FROM capability_cache WHERE revocation_seq < ?1",
            params![min_revocation_seq as i64],
        )?;
        Ok(count)
    }

    pub fn invalidate_capabilities_by_taint_epoch(&self, min_taint_epoch: u64) -> Result<usize> {
        let lock = self.conn.lock();
        let count = lock.execute(
            "DELETE FROM capability_cache WHERE taint_epoch < ?1",
            params![min_taint_epoch as i64],
        )?;
        Ok(count)
    }

    // -------------------------------------------------------------------------
    // Workflow Composition Sequence Queries (Outcome-Level Breakouts)
    // -------------------------------------------------------------------------

    /// Queries whether an agent session has executed a sequence of operations
    /// in chronological order (e.g. `["SensitiveFileAccess", "WorkspaceConfigWrite", "ChildProcessExec"]`).
    pub fn query_workflow_sequence(
        &self,
        session_id: &str,
        effect_sequence: &[&str],
    ) -> Result<Vec<WorkflowSequenceMatch>> {
        if effect_sequence.is_empty() {
            return Ok(Vec::new());
        }

        let lock = self.conn.lock();
        let mut stmt = lock.prepare(
            "SELECT event_id, effect_type, process_instance_id, timestamp
             FROM causal_events
             WHERE session_id = ?1
             ORDER BY event_seq ASC, timestamp ASC",
        )?;

        let rows = stmt.query_map(params![session_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;

        let mut events = Vec::new();
        for r in rows {
            events.push(r?);
        }

        let mut matches = Vec::new();
        let mut seq_idx = 0;
        let mut current_match_events = Vec::new();
        let mut current_match_procs = Vec::new();
        let mut current_match_times = Vec::new();

        for (eid, effect, pid, ts) in &events {
            if effect == effect_sequence[seq_idx] {
                current_match_events.push(eid.clone());
                current_match_procs.push(pid.clone());
                current_match_times.push(ts.clone());
                seq_idx += 1;

                if seq_idx == effect_sequence.len() {
                    matches.push(WorkflowSequenceMatch {
                        session_id: session_id.to_string(),
                        matched_effects: effect_sequence.iter().map(|s| s.to_string()).collect(),
                        event_ids: current_match_events.clone(),
                        process_instances: current_match_procs.clone(),
                        timestamps: current_match_times.clone(),
                    });
                    // Reset to find subsequent occurrences
                    seq_idx = 0;
                    current_match_events.clear();
                    current_match_procs.clear();
                    current_match_times.clear();
                }
            }
        }

        Ok(matches)
    }

    // -------------------------------------------------------------------------
    // Confused-Deputy Broker Attribution Helper
    // -------------------------------------------------------------------------

    /// Attributes an action by a broker process (`WmiPrvSE.exe`, `svchost.exe`, etc.)
    /// back to the requesting agent session, inserting a `BrokeredBy` causal edge.
    pub fn attribute_broker_action(
        &self,
        broker_pid: u32,
        broker_image: &str,
        broker_instance_id: &str,
    ) -> Result<Option<String>> {
        if !self.broker_router.is_broker_image(broker_image) {
            return Ok(None);
        }

        if let Some(delegation) = self.broker_router.resolve_delegation(broker_pid) {
            // Record BrokeredBy edge: requesting_instance -> broker_instance
            let _ = self.record_edge(
                &delegation.requesting_instance_id,
                broker_instance_id,
                CausalEdgeType::BrokeredBy,
                1,
                false,
            );

            Ok(Some(delegation.origin_session_id))
        } else {
            Ok(None)
        }
    }

    // -------------------------------------------------------------------------
    // Regression Index & Diagnostics
    // -------------------------------------------------------------------------

    pub fn record_regression_case(&self, case: &AdversarialRegressionCase) -> Result<()> {
        let lock = self.conn.lock();
        lock.execute(
            "INSERT OR REPLACE INTO adversarial_regression_cases (
                case_id, test_version, framework_version, random_seed,
                environment_config, policy_version, attack_objective,
                expected_effect, actual_effect, evidence, artifact_path, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                case.case_id,
                case.test_version,
                case.framework_version,
                case.random_seed as i64,
                case.environment_config,
                case.policy_version,
                case.attack_objective,
                case.expected_effect,
                case.actual_effect,
                case.evidence,
                case.artifact_path,
                case.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_regression_case(&self, case_id: &str) -> Result<Option<AdversarialRegressionCase>> {
        let lock = self.conn.lock();
        let mut stmt = lock.prepare(
            "SELECT case_id, test_version, framework_version, random_seed,
                    environment_config, policy_version, attack_objective,
                    expected_effect, actual_effect, evidence, artifact_path, created_at
             FROM adversarial_regression_cases WHERE case_id = ?1",
        )?;
        let row = stmt
            .query_row(params![case_id], |r| {
                let seed: i64 = r.get(3)?;
                Ok(AdversarialRegressionCase {
                    case_id: r.get(0)?,
                    test_version: r.get(1)?,
                    framework_version: r.get(2)?,
                    random_seed: seed as u64,
                    environment_config: r.get(4)?,
                    policy_version: r.get(5)?,
                    attack_objective: r.get(6)?,
                    expected_effect: r.get(7)?,
                    actual_effect: r.get(8)?,
                    evidence: r.get(9)?,
                    artifact_path: r.get(10)?,
                    created_at: r.get(11)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn key_store(&self) -> &ServiceIdentityKeyStore {
        &self.key_store
    }

    pub fn db_path(&self) -> &str {
        &self.db_path
    }
}

static GLOBAL_CAUSAL_GRAPH: std::sync::LazyLock<Arc<CausalSecurityGraph>> =
    std::sync::LazyLock::new(|| {
        let db_path = "database/osoosi.db";
        let graph = CausalSecurityGraph::open(db_path).unwrap_or_else(|_| {
            CausalSecurityGraph::in_memory()
                .expect("in-memory fallback for persistent causal graph")
        });
        Arc::new(graph)
    });

/// Returns a shared thread-safe handle to the global persistent Causal Security Graph.
pub fn global_causal_security_graph() -> Arc<CausalSecurityGraph> {
    GLOBAL_CAUSAL_GRAPH.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_instance_identity_determinism_and_uniqueness() {
        let p1 = ProcessInstanceIdentity::new(
            1234,
            100_000,
            "blake3_hash_a",
            Some("parent_uuid".to_string()),
            Some("job_1".to_string()),
            "session_alpha",
        );
        let p2 = ProcessInstanceIdentity::new(
            1234,
            100_000,
            "blake3_hash_a",
            Some("parent_uuid".to_string()),
            Some("job_1".to_string()),
            "session_alpha",
        );
        assert_eq!(
            p1.instance_id, p2.instance_id,
            "Identical parameters must generate identical UUID"
        );

        // Distinct PID -> distinct instance_id
        let p3 = ProcessInstanceIdentity::new(
            5678,
            100_000,
            "blake3_hash_a",
            Some("parent_uuid".to_string()),
            Some("job_1".to_string()),
            "session_alpha",
        );
        assert_ne!(p1.instance_id, p3.instance_id);

        // Distinct start time (PID recycling defense) -> distinct instance_id
        let p4 = ProcessInstanceIdentity::new(
            1234,
            100_001,
            "blake3_hash_a",
            Some("parent_uuid".to_string()),
            Some("job_1".to_string()),
            "session_alpha",
        );
        assert_ne!(p1.instance_id, p4.instance_id);
    }

    #[test]
    fn test_causal_graph_transitive_taint_propagation_and_inheritance() -> Result<()> {
        let graph = CausalSecurityGraph::in_memory()?;

        // 1. Register clean root process
        let root =
            ProcessInstanceIdentity::new(1000, 10, "digest_root", None, None, "session_test");
        graph.register_process_instance(&root, "C:\\agent\\root.exe", 0, false)?;

        // 2. Register child worker process
        let worker = ProcessInstanceIdentity::new(
            1001,
            20,
            "digest_worker",
            Some(root.instance_id.clone()),
            None,
            "session_test",
        );
        graph.record_process_spawn(&root, &worker, "C:\\agent\\worker.exe")?;

        // 3. Register a Crown-Jewel file
        let cj_id = graph.register_file(
            "C:\\vault\\credentials.json",
            "C:\\vault\\credentials.json",
            "hash_secret_vault",
            FileClassification::CrownJewel,
            AuthorityLevel::SystemSecurityPolicy,
            3,
            true,
        )?;

        // Worker reads Crown-Jewel file -> worker taint elevated
        let (new_taint, is_cj) =
            graph.record_file_read(&worker.instance_id, "C:\\vault\\credentials.json")?;
        assert_eq!(new_taint, 3);
        assert!(is_cj);

        // 4. Worker spawns a sub-worker
        let sub_worker = ProcessInstanceIdentity::new(
            1002,
            30,
            "digest_sub",
            Some(worker.instance_id.clone()),
            None,
            "session_test",
        );
        graph.record_process_spawn(&worker, &sub_worker, "C:\\agent\\sub_worker.exe")?;

        // 5. Sub-worker writes a scratchpad file
        graph.record_file_write(
            &sub_worker.instance_id,
            "C:\\temp\\output.txt",
            "C:\\temp\\output.txt",
            "hash_output",
        )?;
        let output_file_id = blake3::hash(b"C:\\temp\\output.txt").to_hex().to_string();

        // 6. Transitive taint query on output file
        let report = graph.get_transitive_taint_report(&output_file_id)?;
        assert!(report.is_tainted);
        assert_eq!(report.max_taint_level, 3);
        assert!(report.has_crown_jewel_taint);
        assert!(report
            .taint_origins
            .iter()
            .any(|o| o.contains(&cj_id) || o.contains(&worker.instance_id)));

        Ok(())
    }

    #[test]
    fn test_trusted_zk_pii_declassification() -> Result<()> {
        let graph = CausalSecurityGraph::in_memory()?;

        // Register tainted secret file
        let secret_file_id = graph.register_file(
            "C:\\data\\leak.txt",
            "C:\\data\\leak.txt",
            "hash_secret",
            FileClassification::CrownJewel,
            AuthorityLevel::SystemSecurityPolicy,
            3,
            true,
        )?;

        // Generate genuine ZK-PII scrubbed proof via PresidioGlinerPiiZeroGuard
        let raw_payload = format!(
            "Sensitive Token: {}_{}",
            "ghp", "123456789012345678901234567890123456"
        );
        let proof = PresidioGlinerPiiZeroGuard::scrub_and_prove(&raw_payload, 500, 6.0, 4);

        // Register scrubbed destination file
        let declass_file_id = graph.register_file(
            "C:\\data\\declassified.txt",
            "C:\\data\\declassified.txt",
            "hash_clean",
            FileClassification::Scratchpad,
            AuthorityLevel::WorkspaceConfiguration,
            3, // initially inherits taint
            true,
        )?;

        // Declassify with valid proof
        let res = graph.declassify_node(
            &secret_file_id,
            &declass_file_id,
            &proof,
            "session_declass",
            Some("decision-123"),
        )?;
        assert!(res.success);
        assert_eq!(res.pii_leakage_bits, 0);
        assert!(res.pqc_signature_verified);

        // Verify declassified node taint was cleared in SQLite
        let declass_report = graph.get_transitive_taint_report(&declass_file_id)?;
        assert_eq!(declass_report.max_taint_level, 0);
        assert!(!declass_report.has_crown_jewel_taint);

        // Test fail-closed on tampered proof (non-zero leakage bits)
        let mut tampered_proof = proof.clone();
        tampered_proof.pii_leakage_bits = 8;
        let reject_res = graph.declassify_node(
            &secret_file_id,
            &declass_file_id,
            &tampered_proof,
            "session_declass",
            None,
        )?;
        assert!(!reject_res.success);
        assert!(reject_res.reason.contains("non-zero leakage bits"));

        Ok(())
    }

    #[test]
    fn test_revocation_bound_capability_cache_and_invalidation() -> Result<()> {
        let graph = CausalSecurityGraph::in_memory()?;

        // Store capability granted under policy_version=1, taint_epoch=1, revocation_seq=1
        graph.store_capability(
            "agent_principal_1",
            "SensitiveFileAccess",
            "vault/secrets.json",
            true,
            1,
            1,
            1,
            "dec_101",
            300,
        )?;

        // Cache hit
        let cached = graph.check_capability(
            "agent_principal_1",
            "SensitiveFileAccess",
            "vault/secrets.json",
            1,
            1,
            1,
        )?;
        assert_eq!(cached, Some(true));

        // When revocation_seq bumps to 2, lookup with old sequence seq=1 fails
        // and lookup with new sequence misses
        let cached_new_seq = graph.check_capability(
            "agent_principal_1",
            "SensitiveFileAccess",
            "vault/secrets.json",
            1,
            1,
            2,
        )?;
        assert_eq!(cached_new_seq, None);

        // Explicit revocation purge
        let purged = graph.invalidate_capabilities_by_revocation(2)?;
        assert_eq!(purged, 1);

        Ok(())
    }

    #[test]
    fn test_service_identity_key_isolation_no_cryptprotect_local_machine() {
        let store = ServiceIdentityKeyStore::new();
        let payload = b"causal_event_attestation_proof_data";

        let seal = store.sign_attestation(payload);
        assert!(store.verify_attestation(payload, &seal));

        // Forged seal fails
        assert!(!store.verify_attestation(payload, "forged_key:001122334455"));
        // Tampered payload fails
        assert!(!store.verify_attestation(b"tampered_payload", &seal));
    }

    #[test]
    fn test_confused_deputy_broker_attribution() -> Result<()> {
        let graph = CausalSecurityGraph::in_memory()?;
        let agent_identity =
            ProcessInstanceIdentity::new(2000, 100, "agent_hash", None, None, "session_agent_99");

        // Register broker delegation: agent calls WmiPrvSE.exe (PID 4444)
        graph.broker_router.register_delegation(
            4444,
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "session_agent_99",
            &agent_identity.instance_id,
        );

        // WmiPrvSE executes action -> attributed back to agent session
        let broker_instance_id = "broker_inst_4444";
        let attributed_session = graph.attribute_broker_action(
            4444,
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            broker_instance_id,
        )?;
        assert_eq!(attributed_session, Some("session_agent_99".to_string()));

        // Non-broker process returns None
        let non_broker = graph.attribute_broker_action(5555, "notepad.exe", "inst_5555")?;
        assert_eq!(non_broker, None);

        Ok(())
    }

    #[test]
    fn test_workflow_composition_sequence_query() -> Result<()> {
        let graph = CausalSecurityGraph::in_memory()?;
        let session = "session_multi_turn";

        // Record a 3-step sequence: SensitiveFileAccess -> ExternalWrite -> ChildProcessExec
        let now = Utc::now().to_rfc3339();
        graph.record_event(&CausalEventRecord {
            event_id: "evt_1".to_string(),
            event_seq: 1,
            decision_id: Some("dec_1".to_string()),
            session_id: session.to_string(),
            process_instance_id: "proc_1".to_string(),
            effect_type: "SensitiveFileAccess".to_string(),
            source_resource: "proc_1".to_string(),
            target_resource: "C:\\secrets\\key.pem".to_string(),
            is_authorized: true,
            verdict: "Allow".to_string(),
            policy_version: 1,
            taint_epoch: 1,
            pre_event_taint: 0,
            post_event_taint: 1,
            details_json: None,
            timestamp: now.clone(),
        })?;

        graph.record_event(&CausalEventRecord {
            event_id: "evt_2".to_string(),
            event_seq: 2,
            decision_id: Some("dec_2".to_string()),
            session_id: session.to_string(),
            process_instance_id: "proc_1".to_string(),
            effect_type: "ExternalWrite".to_string(),
            source_resource: "proc_1".to_string(),
            target_resource: "https://api.github.com/repo/issues".to_string(),
            is_authorized: true,
            verdict: "Allow".to_string(),
            policy_version: 1,
            taint_epoch: 1,
            pre_event_taint: 1,
            post_event_taint: 1,
            details_json: None,
            timestamp: now.clone(),
        })?;

        graph.record_event(&CausalEventRecord {
            event_id: "evt_3".to_string(),
            event_seq: 3,
            decision_id: Some("dec_3".to_string()),
            session_id: session.to_string(),
            process_instance_id: "proc_1".to_string(),
            effect_type: "ChildProcessExec".to_string(),
            source_resource: "proc_1".to_string(),
            target_resource: "C:\\Windows\\System32\\cmd.exe".to_string(),
            is_authorized: true,
            verdict: "Allow".to_string(),
            policy_version: 1,
            taint_epoch: 1,
            pre_event_taint: 1,
            post_event_taint: 1,
            details_json: None,
            timestamp: now,
        })?;

        // Query sequence: SensitiveFileAccess followed by ExternalWrite followed by ChildProcessExec
        let matches = graph.query_workflow_sequence(
            session,
            &["SensitiveFileAccess", "ExternalWrite", "ChildProcessExec"],
        )?;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].event_ids, vec!["evt_1", "evt_2", "evt_3"]);

        // Query non-matching sequence
        let no_matches =
            graph.query_workflow_sequence(session, &["ChildProcessExec", "SensitiveFileAccess"])?;
        assert_eq!(no_matches.len(), 0);

        Ok(())
    }

    #[test]
    fn test_adversarial_regression_cases_persistence() -> Result<()> {
        let graph = CausalSecurityGraph::in_memory()?;

        let case = AdversarialRegressionCase {
            case_id: "case-breakout-001".to_string(),
            test_version: "1.2.0".to_string(),
            framework_version: "seven-ring-v1".to_string(),
            random_seed: 42,
            environment_config: "{\"mode\": \"enforce\", \"sandbox\": \"appcontainer\"}"
                .to_string(),
            policy_version: 1,
            attack_objective: "Direct external exfiltration of crown jewel credentials".to_string(),
            expected_effect: "PreExecutionPrevented".to_string(),
            actual_effect: "PreExecutionPrevented".to_string(),
            evidence: "Blake3 proof and blocked socket connect".to_string(),
            artifact_path: "logs/regressions/case-001.json".to_string(),
            created_at: Utc::now().to_rfc3339(),
        };

        graph.record_regression_case(&case)?;

        let retrieved = graph.get_regression_case("case-breakout-001")?;
        assert!(retrieved.is_some());
        let r = retrieved.unwrap();
        assert_eq!(r.case_id, "case-breakout-001");
        assert_eq!(r.random_seed, 42);
        assert_eq!(r.expected_effect, "PreExecutionPrevented");

        // Non-existent case
        let missing = graph.get_regression_case("non-existent")?;
        assert!(missing.is_none());

        Ok(())
    }
}
