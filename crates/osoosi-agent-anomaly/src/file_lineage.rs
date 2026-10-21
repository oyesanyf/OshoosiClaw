//! BLAKE3 Input-File Lineage Tracker (`FileLineageTracker`).
//!
//! Provides strict attribution of input files, documents, and web payloads across agent
//! execution sessions. Enforces 16,384-entry bounded maps with FIFO eviction and hard immunity
//! preventing project repository files and developer/system binaries from being quarantined or poisoned.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use osoosi_types::{
    is_developer_interpreter, is_protected_os_shell_or_desktop_binary, resolve_project_root,
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{info, warn};

/// Default bounded map capacity for session files and lineage records.
pub const DEFAULT_MAX_CAPACITY: usize = 16_384;

/// Represents an ingested input file or document tracked in agent session lineage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LineageEntry {
    pub session_id: String,
    pub path: PathBuf,
    pub blake3_digest: String,
    pub ingested_at: DateTime<Utc>,
    pub is_immune: bool,
}

/// Backwards-compatible alias for LineageEntry.
pub type IngestedFileEntry = LineageEntry;

/// Metadata associated with a poisoned or adversarial payload digest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoisonMetadata {
    pub digest: String,
    pub reason: String,
    pub source_session: String,
    pub poisoned_at: DateTime<Utc>,
    pub confidence: f64,
}

/// Errors produced during file lineage tracking and verification.
#[derive(Debug, thiserror::Error)]
pub enum LineageError {
    #[error("Target is immune from poisoning or quarantine: {0}")]
    ImmuneTarget(String),
    #[error("Capacity limit exceeded: {0}")]
    CapacityExceeded(String),
    #[error("IO error while reading target path: {0}")]
    Io(#[from] std::io::Error),
    #[error("Poisoned digest detected: {0}")]
    PoisonedDigest(String),
    #[error("Serialization or parsing error: {0}")]
    Serialization(String),
    #[error("General lineage error: {0}")]
    General(String),
}

/// Thread-safe bounded map helper with strict FIFO eviction.
struct BoundedMap<K, V> {
    max_capacity: usize,
    map: DashMap<K, V>,
    queue: Mutex<VecDeque<K>>,
}

impl<K: std::hash::Hash + Eq + Clone + Send + Sync, V: Clone> BoundedMap<K, V> {
    fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity,
            map: DashMap::new(),
            queue: Mutex::new(VecDeque::new()),
        }
    }

    fn insert(&self, key: K, value: V) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if !self.map.contains_key(&key) {
            while q.len() >= self.max_capacity {
                if let Some(oldest) = q.pop_front() {
                    self.map.remove(&oldest);
                }
            }
            q.push_back(key.clone());
        }
        self.map.insert(key, value);
    }

    fn get(&self, key: &K) -> Option<V> {
        self.map.get(key).map(|v| v.value().clone())
    }

    fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    #[allow(dead_code)]
    fn remove(&self, key: &K) -> Option<V> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.retain(|k| k != key);
        self.map.remove(key).map(|(_, v)| v)
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn values(&self) -> Vec<V> {
        self.map.iter().map(|kv| kv.value().clone()).collect()
    }
}

/// Bounded BLAKE3 File Lineage Tracker for Agent Sessions.
pub struct FileLineageTracker {
    pub max_capacity: usize,
    session_files: DashMap<String, VecDeque<LineageEntry>>,
    session_order: Mutex<VecDeque<String>>,
    known_paths_by_digest: BoundedMap<String, PathBuf>,
    poisoned_digests: BoundedMap<String, PoisonMetadata>,
    seen_alerts: BoundedMap<String, DateTime<Utc>>,
    total_ingested_count: Mutex<usize>,
}

impl Default for FileLineageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FileLineageTracker {
    /// Create a new `FileLineageTracker` with default capacity of 16,384 entries.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_CAPACITY)
    }

    /// Create a new `FileLineageTracker` with custom bounded capacity.
    pub fn with_capacity(max_capacity: usize) -> Self {
        let cap = if max_capacity == 0 { DEFAULT_MAX_CAPACITY } else { max_capacity };
        Self {
            max_capacity: cap,
            session_files: DashMap::new(),
            session_order: Mutex::new(VecDeque::new()),
            known_paths_by_digest: BoundedMap::new(cap),
            poisoned_digests: BoundedMap::new(cap),
            seen_alerts: BoundedMap::new(cap),
            total_ingested_count: Mutex::new(0),
        }
    }

    /// Computes the standard BLAKE3 hex digest for the given byte slice.
    pub fn compute_blake3(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    /// Read file content and compute its BLAKE3 hash.
    pub fn compute_file_blake3(path: &Path) -> std::io::Result<String> {
        let bytes = std::fs::read(path)?;
        Ok(Self::compute_blake3(&bytes))
    }

    /// Returns true if the target path or binary is protected under hard immunity invariants.
    /// Repository sources, developer toolchains, and critical OS binaries can NEVER be poisoned or quarantined.
    pub fn is_path_immune(&self, path: &Path) -> bool {
        // 1. Check workspace repository root
        if let Some(root) = resolve_project_root() {
            if path.starts_with(&root) {
                return true;
            }
            if let Ok(canon_path) = path.canonicalize() {
                if let Ok(canon_root) = root.canonicalize() {
                    if canon_path.starts_with(&canon_root) {
                        return true;
                    }
                }
            }
        }

        let path_str = path.to_string_lossy();
        // 2. Check developer interpreters (python, node, ruby, perl, etc.)
        if is_developer_interpreter(&path_str) {
            return true;
        }

        // 3. Check protected OS shells and system binaries
        if is_protected_os_shell_or_desktop_binary(&path_str) {
            return true;
        }

        // Check filename component directly
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if is_developer_interpreter(file_name) || is_protected_os_shell_or_desktop_binary(file_name) {
                return true;
            }
        }

        false
    }

    /// Check if a BLAKE3 digest has been identified and marked as poisoned.
    pub fn is_poisoned_digest(&self, digest: &str) -> bool {
        self.poisoned_digests.contains_key(&digest.to_lowercase())
    }

    /// Alias for `is_poisoned_digest`.
    pub fn is_digest_poisoned(&self, digest: &str) -> bool {
        self.is_poisoned_digest(digest)
    }

    /// Mark a BLAKE3 digest as poisoned, rejecting any attempts to poison immune paths.
    pub fn mark_digest_poisoned(
        &self,
        digest: &str,
        session_id: &str,
        reason: &str,
        confidence: f64,
    ) -> Result<bool, LineageError> {
        let digest_norm = digest.trim().to_lowercase();
        if digest_norm.is_empty() {
            return Ok(false);
        }

        // If we know the file path for this digest, ensure it is not immune
        if let Some(known_path) = self.known_paths_by_digest.get(&digest_norm) {
            if self.is_path_immune(&known_path) {
                warn!(
                    "IMMUNITY ENFORCED: Refused to poison immune path {:?} (digest: {})",
                    known_path, digest_norm
                );
                return Err(LineageError::ImmuneTarget(format!(
                    "Path {:?} is immune from poisoning",
                    known_path
                )));
            }
        }

        let metadata = PoisonMetadata {
            digest: digest_norm.clone(),
            reason: reason.to_string(),
            source_session: session_id.to_string(),
            poisoned_at: Utc::now(),
            confidence: confidence.clamp(0.0, 1.0),
        };

        info!(
            "LINEAGE: Poisoned digest registered: {} (session: {}, reason: {})",
            digest_norm, session_id, reason
        );
        self.poisoned_digests.insert(digest_norm, metadata);
        Ok(true)
    }

    /// Swarm pre-immunization helper: mark a digest as poisoned across the swarm.
    pub fn immunize_poisoned_digest(&self, digest: &str, reason: &str) -> Result<(), LineageError> {
        self.mark_digest_poisoned(digest, "swarm_consensus", reason, 1.00)?;
        Ok(())
    }

    /// Record an ingested file under a given agent session.
    /// If content is provided, BLAKE3 is computed directly; otherwise the file is read from disk.
    /// Fails immediately if the file matches a previously poisoned digest.
    pub fn record_ingested_file(
        &self,
        session_id: &str,
        path: &Path,
        content: &[u8],
    ) -> Result<String, LineageError> {
        let digest = if !content.is_empty() {
            Self::compute_blake3(content)
        } else if path.exists() {
            Self::compute_file_blake3(path)?
        } else {
            Self::compute_blake3(path.to_string_lossy().as_bytes())
        }
        .to_lowercase();

        let is_immune = self.is_path_immune(path);

        // Check if digest has been poisoned (immune repository & OS files are never blocked)
        if !is_immune && self.is_poisoned_digest(&digest) {
            warn!(
                "SECURITY ALERT: Blocked ingestion of poisoned file {:?} (digest: {}) in session {}",
                path, digest, session_id
            );
            return Err(LineageError::PoisonedDigest(format!(
                "File {:?} matches swarm-poisoned digest {}",
                path, digest
            )));
        }

        let entry = LineageEntry {
            session_id: session_id.to_string(),
            path: path.to_path_buf(),
            blake3_digest: digest.clone(),
            ingested_at: Utc::now(),
            is_immune,
        };

        // Manage session_files map-level bounded capacity with FIFO eviction
        {
            let mut order = self.session_order.lock().unwrap_or_else(|e| e.into_inner());
            if !self.session_files.contains_key(session_id) {
                while order.len() >= self.max_capacity {
                    if let Some(oldest_session) = order.pop_front() {
                        self.session_files.remove(&oldest_session);
                    }
                }
                order.push_back(session_id.to_string());
            }
        }

        // Record into session lineage with FIFO capping per session
        let mut session_entries = self
            .session_files
            .entry(session_id.to_string())
            .or_insert_with(VecDeque::new);

        while session_entries.len() >= self.max_capacity {
            session_entries.pop_front();
        }
        session_entries.push_back(entry);
        drop(session_entries);

        // Record into global path-by-digest mapping
        self.known_paths_by_digest.insert(digest.clone(), path.to_path_buf());

        // Increment global counter
        let mut total = self.total_ingested_count.lock().unwrap_or_else(|e| e.into_inner());
        *total = total.saturating_add(1);

        Ok(digest)
    }

    /// Attribute a canary alert to the most recent non-immune file ingested in the session.
    /// Automatically marks the attributed file's digest as poisoned.
    pub fn attribute_canary_alert(
        &self,
        session_id: &str,
        alert_id: &str,
        trap_path: &str,
    ) -> Option<String> {
        self.seen_alerts.insert(alert_id.to_string(), Utc::now());

        if let Some(session_entries) = self.session_files.get(session_id) {
            // Find most recent non-immune ingested file
            for entry in session_entries.iter().rev() {
                if !entry.is_immune {
                    let digest = entry.blake3_digest.clone();
                    let reason = format!(
                        "Canary trap triggered ({}) in session {} via trap {}",
                        alert_id, session_id, trap_path
                    );
                    let _ = self.mark_digest_poisoned(&digest, session_id, &reason, 1.00);
                    return Some(digest);
                }
            }
        }
        None
    }

    /// Inspect tool call parameters (JSON) for references to poisoned file paths or hashes.
    pub fn inspect_tool_call_parameters(&self, params: &serde_json::Value) -> Result<(), LineageError> {
        match params {
            serde_json::Value::String(s) => {
                let trimmed = s.trim().to_lowercase();
                if self.is_poisoned_digest(&trimmed) {
                    return Err(LineageError::PoisonedDigest(format!(
                        "Parameter contains poisoned digest: {}",
                        trimmed
                    )));
                }
                // Check if string is a path whose hash is poisoned
                let p = Path::new(s);
                if p.is_file() && !self.is_path_immune(p) {
                    if let Ok(digest) = Self::compute_file_blake3(p) {
                        if self.is_poisoned_digest(&digest) {
                            return Err(LineageError::PoisonedDigest(format!(
                                "Parameter references poisoned file {:?} with digest {}",
                                p, digest
                            )));
                        }
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.inspect_tool_call_parameters(item)?;
                }
            }
            serde_json::Value::Object(map) => {
                for (_, val) in map {
                    self.inspect_tool_call_parameters(val)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns all lineage entries for a given session.
    pub fn get_session_lineage(&self, session_id: &str) -> Vec<LineageEntry> {
        self.session_files
            .get(session_id)
            .map(|dq| dq.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the number of active tracked sessions in session_files.
    pub fn session_count(&self) -> usize {
        self.session_files.len()
    }

    /// Returns the count of currently registered poisoned digests.
    pub fn poisoned_count(&self) -> usize {
        self.poisoned_digests.len()
    }

    /// Returns all poisoned metadata entries.
    pub fn get_all_poisoned_digests(&self) -> Vec<PoisonMetadata> {
        self.poisoned_digests.values()
    }

    /// Clear all session lineage state (useful for test resets).
    pub fn clear(&self) {
        self.session_files.clear();
        let mut order = self.session_order.lock().unwrap_or_else(|e| e.into_inner());
        order.clear();

        let mut q_paths = self.known_paths_by_digest.queue.lock().unwrap_or_else(|e| e.into_inner());
        q_paths.clear();
        self.known_paths_by_digest.map.clear();

        let mut q_poison = self.poisoned_digests.queue.lock().unwrap_or_else(|e| e.into_inner());
        q_poison.clear();
        self.poisoned_digests.map.clear();

        let mut q_alerts = self.seen_alerts.queue.lock().unwrap_or_else(|e| e.into_inner());
        q_alerts.clear();
        self.seen_alerts.map.clear();

        let mut total = self.total_ingested_count.lock().unwrap_or_else(|e| e.into_inner());
        *total = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hashing() {
        let content = b"Agentic EDR BLAKE3 Lineage Payload";
        let hash1 = FileLineageTracker::compute_blake3(content);
        let hash2 = blake3::hash(content).to_hex().to_string();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_fifo_eviction_at_capacity() {
        let tracker = FileLineageTracker::with_capacity(5);
        for i in 0..10 {
            let digest = format!("{:064x}", i);
            let res = tracker.mark_digest_poisoned(&digest, "test_session", "synthetic_test", 1.0);
            assert!(res.is_ok());
        }

        // Bounded capacity must never exceed 5
        assert_eq!(tracker.poisoned_count(), 5);

        // Oldest entries (0..5) should have been evicted
        assert!(!tracker.is_poisoned_digest(&format!("{:064x}", 0)));
        assert!(!tracker.is_poisoned_digest(&format!("{:064x}", 4)));

        // Newest entries (5..10) must be present
        assert!(tracker.is_poisoned_digest(&format!("{:064x}", 5)));
        assert!(tracker.is_poisoned_digest(&format!("{:064x}", 9)));
    }

    #[test]
    fn test_repository_file_immunity() {
        let tracker = FileLineageTracker::new();

        // Project root immunity
        if let Some(root) = resolve_project_root() {
            let repo_file = root.join("Cargo.toml");
            assert!(tracker.is_path_immune(&repo_file));

            let digest = "1111111111111111111111111111111111111111111111111111111111111111";
            tracker.known_paths_by_digest.insert(digest.to_string(), repo_file);

            // Poisoning attempt on immune repo path MUST fail
            let poison_res = tracker.mark_digest_poisoned(digest, "session_test", "attack", 1.0);
            assert!(poison_res.is_err());
            assert!(!tracker.is_poisoned_digest(digest));
        }

        // Developer interpreter immunity
        assert!(tracker.is_path_immune(Path::new("python.exe")));
        assert!(tracker.is_path_immune(Path::new("node.exe")));
        assert!(tracker.is_path_immune(Path::new("cargo.exe")));
    }

    #[test]
    fn test_poisoned_digest_tracking_and_blocking() {
        let tracker = FileLineageTracker::new();
        let untrusted_file = Path::new("C:\\temp\\untrusted_payload.txt");
        let content = b"Malicious Injected Document Content";

        // Ingest clean file first
        let digest = tracker
            .record_ingested_file("session_a", untrusted_file, content)
            .expect("Clean ingestion should succeed");

        assert_eq!(tracker.get_session_lineage("session_a").len(), 1);

        // Mark digest poisoned
        tracker
            .mark_digest_poisoned(&digest, "session_a", "adversarial prompt injection", 1.0)
            .expect("Marking poison should succeed");

        assert!(tracker.is_poisoned_digest(&digest));

        // Attempting to ingest the same poisoned payload in another session MUST be blocked
        let blocked = tracker.record_ingested_file("session_b", untrusted_file, content);
        assert!(blocked.is_err());
        match blocked.unwrap_err() {
            LineageError::PoisonedDigest(msg) => {
                assert!(msg.contains(&digest));
            }
            other => panic!("Expected PoisonedDigest error, got {:?}", other),
        }
    }

    #[test]
    fn test_canary_alert_attribution() {
        let tracker = FileLineageTracker::new();
        let untrusted_file = Path::new("C:\\external\\phishing_report.pdf");
        let content = b"Fake PDF with embedded Canary Trigger";

        let digest = tracker
            .record_ingested_file("session_victim", untrusted_file, content)
            .expect("Ingestion should succeed");

        let attributed = tracker.attribute_canary_alert(
            "session_victim",
            "alert_999",
            r"\\.\pipe\osoosi_canary_session_victim_deadbeef",
        );

        assert_eq!(attributed, Some(digest.clone()));
        assert!(tracker.is_poisoned_digest(&digest));
    }

    #[test]
    fn test_session_files_fifo_eviction_at_capacity() {
        let tracker = FileLineageTracker::with_capacity(3);
        let dummy_path = Path::new("C:\\temp\\dummy.txt");
        let content = b"dummy content";

        for i in 0..5 {
            let session_id = format!("session_{}", i);
            let res = tracker.record_ingested_file(&session_id, dummy_path, content);
            assert!(res.is_ok());
        }

        // Must strictly not exceed max_capacity of 3 sessions
        assert_eq!(tracker.session_count(), 3);

        // Oldest sessions (0 and 1) should be evicted
        assert!(tracker.get_session_lineage("session_0").is_empty());
        assert!(tracker.get_session_lineage("session_1").is_empty());

        // Newest sessions (2, 3, 4) must be present
        assert_eq!(tracker.get_session_lineage("session_2").len(), 1);
        assert_eq!(tracker.get_session_lineage("session_3").len(), 1);
        assert_eq!(tracker.get_session_lineage("session_4").len(), 1);
    }

    #[test]
    fn test_immune_file_ingestion_not_blocked_by_poisoned_digest() {
        let tracker = FileLineageTracker::new();

        if let Some(root) = resolve_project_root() {
            let repo_file = root.join("Cargo.toml");
            assert!(tracker.is_path_immune(&repo_file));

            // Compute hash of the actual file
            let digest = FileLineageTracker::compute_file_blake3(&repo_file).unwrap();

            // Simulate that an attacker or swarm peer managed to insert this hash into poisoned_digests
            tracker.poisoned_digests.insert(
                digest.clone(),
                PoisonMetadata {
                    digest: digest.clone(),
                    reason: "malicious hash collision attempt".to_string(),
                    source_session: "external_attacker".to_string(),
                    poisoned_at: Utc::now(),
                    confidence: 1.0,
                },
            );
            assert!(tracker.is_poisoned_digest(&digest));

            // Ingesting the immune repo file MUST succeed despite hash being in poisoned_digests
            let res = tracker.record_ingested_file("test_session", &repo_file, b"");
            assert!(res.is_ok(), "Immune repository file must not be blocked: {:?}", res);
            assert_eq!(res.unwrap(), digest);

            // Verify entry was recorded with is_immune = true
            let lineage = tracker.get_session_lineage("test_session");
            assert_eq!(lineage.len(), 1);
            assert!(lineage[0].is_immune);
        }
    }
}
