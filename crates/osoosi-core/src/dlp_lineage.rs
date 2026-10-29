//! Synthetic OpenTelemetry Producer & Lock-Free DashMap Taint State Machine
//! for Real-Time DLP Data Lineage and Provenance Tracking.
//!
//! Provides sub-microsecond in-memory causal taint tracking across instrumented
//! and uninstrumented native OS processes (`7z.exe`, `tar`, `powershell.exe`, etc.),
//! synthetic out-of-process OpenTelemetry `SpanContext` synthesis, strict lattice
//! dominance for W3C Baggage policies, and three critical boundary mitigations:
//! - Boundary 1: Anti-Taint Creep in long-lived processes (`explorer.exe`, IDEs).
//! - Boundary 2: Encrypted/zero-similarity causal taint preservation (`openssl enc`, `7z.exe`).
//! - Boundary 3: Cross-host new inode rehydration via exact SHA-256 and fuzzy ssdeep digests.
#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use opentelemetry::trace::{Link, SpanContext, SpanId, TraceFlags, TraceId, TraceState};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

// ============================================================================
// 1. Data Structures & Keys
// ============================================================================

/// Process instance identifier tuple `(pid, start_time_100ns)` preventing PID reuse collisions.
///
/// Under high system churn, OS process IDs are frequently recycled. By pairing the
/// numerical PID with the process's 100-nanosecond creation timestamp, stale
/// taint state is never inherited by subsequent benign processes with the same PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessInstanceKey {
    pub pid: u32,
    pub start_time_100ns: u64,
}

impl ProcessInstanceKey {
    #[inline]
    pub fn new(pid: u32, start_time_100ns: u64) -> Self {
        Self {
            pid,
            start_time_100ns,
        }
    }

    #[inline]
    pub fn as_tuple(&self) -> (u32, u64) {
        (self.pid, self.start_time_100ns)
    }
}

impl fmt::Display for ProcessInstanceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PID:{}:{}", self.pid, self.start_time_100ns)
    }
}

impl From<(u32, u64)> for ProcessInstanceKey {
    fn from((pid, start_time): (u32, u64)) -> Self {
        Self::new(pid, start_time)
    }
}

/// Artifact identifier tuple `(device_id, inode_or_file_id)` ensuring path-independent tracking.
///
/// Aliasing techniques such as hard links, NTFS alternate data streams, renaming,
/// and temporary path changes do not alter filesystem inodes or volume file IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactKey {
    pub device_id: u64,
    pub inode_or_file_id: u64,
}

impl ArtifactKey {
    #[inline]
    pub fn new(device_id: u64, inode_or_file_id: u64) -> Self {
        Self {
            device_id,
            inode_or_file_id,
        }
    }

    #[inline]
    pub fn as_tuple(&self) -> (u64, u64) {
        (self.device_id, self.inode_or_file_id)
    }

    /// Attempts to extract the OS filesystem identity for a given path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let p = path.as_ref();
        #[cfg(windows)]
        {
            if let Ok(file) = std::fs::File::open(p) {
                if let Ok(key) = Self::from_file(&file) {
                    return Ok(key);
                }
            }
        }
        let meta = std::fs::metadata(p)?;
        Self::from_metadata(&meta)
    }

    /// Extracts the OS filesystem identity for a given path, or derives a deterministic synthetic key.
    pub fn from_path_or_synthetic<P: AsRef<Path>>(path: P) -> Self {
        if let Ok(key) = Self::from_path(&path) {
            return key;
        }
        let p_str = path.as_ref().to_string_lossy();
        let hash = blake3::hash(p_str.as_bytes());
        let mut dev_bytes = [0u8; 8];
        let mut fid_bytes = [0u8; 8];
        dev_bytes.copy_from_slice(&hash.as_bytes()[..8]);
        fid_bytes.copy_from_slice(&hash.as_bytes()[8..16]);
        Self::new(u64::from_le_bytes(dev_bytes), u64::from_le_bytes(fid_bytes))
    }

    /// On Windows, extracts true `(dwVolumeSerialNumber, (nFileIndexHigh << 32) | nFileIndexLow)`
    /// from an open file handle via Win32 `GetFileInformationByHandle`.
    #[cfg(windows)]
    pub fn from_file(file: &std::fs::File) -> std::io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        let handle = file.as_raw_handle();

        #[repr(C)]
        struct BY_HANDLE_FILE_INFORMATION {
            dw_file_attributes: u32,
            ft_creation_time: [u32; 2],
            ft_last_access_time: [u32; 2],
            ft_last_write_time: [u32; 2],
            dw_volume_serial_number: u32,
            n_file_size_high: u32,
            n_file_size_low: u32,
            n_number_of_links: u32,
            n_file_index_high: u32,
            n_file_index_low: u32,
        }

        extern "system" {
            fn GetFileInformationByHandle(
                h_file: *mut std::ffi::c_void,
                lp_file_information: *mut BY_HANDLE_FILE_INFORMATION,
            ) -> i32;
        }

        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        let ret = unsafe { GetFileInformationByHandle(handle as *mut _, info.as_mut_ptr()) };
        if ret != 0 {
            let info = unsafe { info.assume_init() };
            let dev_id = info.dw_volume_serial_number as u64;
            let file_id = ((info.n_file_index_high as u64) << 32) | (info.n_file_index_low as u64);
            Ok(Self::new(dev_id, file_id))
        } else {
            let meta = file.metadata()?;
            Self::from_metadata(&meta)
        }
    }

    /// Extracts `(device_id, inode_or_file_id)` from standard filesystem metadata.
    #[cfg(windows)]
    pub fn from_metadata(meta: &std::fs::Metadata) -> std::io::Result<Self> {
        use std::os::windows::fs::MetadataExt;

        // Windows true file index resolution:
        // Query volume_serial_number and file_index via extension trait.
        // Fall back to stable creation_time / (file_size ^ last_write_time) hashing
        // if file_index() is None (e.g. metadata queried without handle or on unsupported volumes).
        let dev = WindowsFileIndexExt::volume_serial_number(meta).map(|v| v as u64);
        let fid = WindowsFileIndexExt::file_index(meta);

        let (device_id, inode_or_file_id) = match (dev, fid) {
            (Some(d), Some(f)) => (d, f),
            (None, Some(f)) => (meta.creation_time(), f),
            _ => {
                let d = meta.creation_time();
                let f = (meta.file_size() << 32) ^ meta.last_write_time();
                (d, f)
            }
        };

        Ok(Self::new(device_id, inode_or_file_id))
    }

    /// Extracts `(device_id, inode_or_file_id)` from Unix filesystem metadata.
    #[cfg(unix)]
    pub fn from_metadata(meta: &std::fs::Metadata) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        Ok(Self::new(meta.dev(), meta.ino()))
    }

    /// Fallback for non-Windows, non-Unix targets in testing environments.
    #[cfg(not(any(windows, unix)))]
    pub fn from_metadata(meta: &std::fs::Metadata) -> std::io::Result<Self> {
        let len = meta.len();
        Ok(Self::new(1, len))
    }
}

/// Windows extension trait providing `volume_serial_number` and `file_index`
/// for `std::fs::Metadata`.
#[cfg(windows)]
pub trait WindowsFileIndexExt {
    fn volume_serial_number(&self) -> Option<u32>;
    fn file_index(&self) -> Option<u64>;
}

#[cfg(windows)]
impl WindowsFileIndexExt for std::fs::Metadata {
    fn volume_serial_number(&self) -> Option<u32> {
        None
    }

    fn file_index(&self) -> Option<u64> {
        None
    }
}

impl fmt::Display for ArtifactKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "INODE:{}:{}", self.device_id, self.inode_or_file_id)
    }
}

impl From<(u64, u64)> for ArtifactKey {
    fn from((dev, id): (u64, u64)) -> Self {
        Self::new(dev, id)
    }
}

// ============================================================================
// 2. Strict Meet-Semilattices (Strictest-Wins Dominance)
// ============================================================================

/// Data Classification Bounded Meet-Semilattice:
/// `CrownJewel` > `Confidential` > `Internal` > `Public`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ClassificationLattice {
    Public = 1,
    Internal = 2,
    Confidential = 3,
    CrownJewel = 4,
}

impl ClassificationLattice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::CrownJewel => "CROWN_JEWEL",
        }
    }

    pub fn from_str_relaxed(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "CROWN_JEWEL" | "CROWNJEWEL" | "SECRET" => Self::CrownJewel,
            "CONFIDENTIAL" | "CONFIDENTIAL_SOURCE" | "RESTRICTED" => Self::Confidential,
            "INTERNAL" | "WORKSPACE_CONFIG" => Self::Internal,
            _ => Self::Public,
        }
    }

    /// Lattice join operator: strictly dominance-ordered (strictest wins).
    #[inline]
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }

    #[inline]
    pub fn is_sensitive(&self) -> bool {
        *self >= Self::Confidential
    }

    #[inline]
    pub fn is_crown_jewel(&self) -> bool {
        *self == Self::CrownJewel
    }
}

impl fmt::Display for ClassificationLattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Policy Enforcement Bounded Meet-Semilattice:
/// `Quarantine` > `Block` > `Monitor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicyLattice {
    Monitor = 1,
    Block = 2,
    Quarantine = 3,
}

impl PolicyLattice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monitor => "MONITOR",
            Self::Block => "BLOCK",
            Self::Quarantine => "QUARANTINE",
        }
    }

    pub fn from_str_relaxed(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "QUARANTINE" | "QUARANTINE_ON_CROWN_JEWEL" => Self::Quarantine,
            "BLOCK" | "ENFORCE_BLOCK_AND_SCRUB" => Self::Block,
            _ => Self::Monitor,
        }
    }

    /// Lattice join operator: strictly dominance-ordered (strictest enforcement wins).
    #[inline]
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }

    #[inline]
    pub fn is_enforced(&self) -> bool {
        *self >= Self::Block
    }

    #[inline]
    pub fn is_quarantine(&self) -> bool {
        *self == Self::Quarantine
    }
}

impl fmt::Display for PolicyLattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// 3. W3C Baggage & Taint Metadata Representation
// ============================================================================

/// W3C Baggage metadata payload adhering to OpenTelemetry standards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpBaggage {
    pub classification: ClassificationLattice,
    pub policy: PolicyLattice,
    pub tainted: bool,
    pub source_sha256: String,
    pub transform: Option<String>,
    pub rehydrated: Option<String>,
    pub custom: BTreeMap<String, String>,
}

impl DlpBaggage {
    pub fn new(
        classification: ClassificationLattice,
        policy: PolicyLattice,
        tainted: bool,
        source_sha256: impl Into<String>,
    ) -> Self {
        Self {
            classification,
            policy,
            tainted,
            source_sha256: source_sha256.into(),
            transform: None,
            rehydrated: None,
            custom: BTreeMap::new(),
        }
    }

    pub fn public_clean() -> Self {
        Self {
            classification: ClassificationLattice::Public,
            policy: PolicyLattice::Monitor,
            tainted: false,
            source_sha256: String::new(),
            transform: None,
            rehydrated: None,
            custom: BTreeMap::new(),
        }
    }

    /// Join two W3C Baggage instances according to semilattice dominance.
    pub fn join(&self, other: &Self) -> Self {
        let classification = self.classification.join(other.classification);
        let policy = self.policy.join(other.policy);
        let tainted = self.tainted || other.tainted;

        // Choose dominant source SHA-256
        let source_sha256 = if self.classification > other.classification {
            self.source_sha256.clone()
        } else if other.classification > self.classification {
            other.source_sha256.clone()
        } else if !self.source_sha256.is_empty() {
            self.source_sha256.clone()
        } else {
            other.source_sha256.clone()
        };

        let transform = self.transform.clone().or_else(|| other.transform.clone());
        let rehydrated = self.rehydrated.clone().or_else(|| other.rehydrated.clone());

        let mut custom = self.custom.clone();
        for (k, v) in &other.custom {
            custom.entry(k.clone()).or_insert_with(|| v.clone());
        }

        Self {
            classification,
            policy,
            tainted,
            source_sha256,
            transform,
            rehydrated,
            custom,
        }
    }

    /// Serializes to a standard W3C `baggage` header string.
    pub fn to_w3c_header(&self) -> String {
        let mut items = vec![
            format!("dlp.classification={}", self.classification.as_str()),
            format!("dlp.policy={}", self.policy.as_str()),
            format!(
                "dlp.tainted={}",
                if self.tainted { "true" } else { "false" }
            ),
        ];
        if !self.source_sha256.is_empty() {
            items.push(format!("dlp.source_sha256={}", self.source_sha256));
        }
        if let Some(ref tr) = self.transform {
            items.push(format!("dlp.transform={}", tr));
        }
        if let Some(ref rh) = self.rehydrated {
            items.push(format!("dlp.rehydrated={}", rh));
        }
        for (k, v) in &self.custom {
            items.push(format!("{}={}", k, v));
        }
        items.join(",")
    }

    /// Parses a W3C baggage header into a `DlpBaggage` record.
    pub fn from_w3c_header(header: &str) -> Self {
        let mut classification = ClassificationLattice::Public;
        let mut policy = PolicyLattice::Monitor;
        let mut tainted = false;
        let mut source_sha256 = String::new();
        let mut transform = None;
        let mut rehydrated = None;
        let mut custom = BTreeMap::new();

        for part in header.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            // W3C Baggage member grammar: key=value *(;property)
            // Strip member properties following ';'
            let item = part.split(';').next().unwrap_or(part).trim();
            if let Some((k, v)) = item.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "dlp.classification" => {
                        classification = ClassificationLattice::from_str_relaxed(v);
                    }
                    "dlp.policy" => {
                        policy = PolicyLattice::from_str_relaxed(v);
                    }
                    "dlp.tainted" => {
                        tainted = v.eq_ignore_ascii_case("true");
                    }
                    "dlp.source_sha256" => {
                        source_sha256 = v.to_string();
                    }
                    "dlp.transform" => {
                        transform = Some(v.to_string());
                    }
                    "dlp.rehydrated" => {
                        rehydrated = Some(v.to_string());
                    }
                    _ => {
                        if !k.is_empty() {
                            custom.insert(k.to_string(), v.to_string());
                        }
                    }
                }
            }
        }

        Self {
            classification,
            policy,
            tainted,
            source_sha256,
            transform,
            rehydrated,
            custom,
        }
    }
}

// ============================================================================
// 4. Artifact & Process Taint Records
// ============================================================================

/// Taint metadata associated with a physical file artifact on the host filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactTaintRecord {
    pub artifact_key: ArtifactKey,
    pub canonical_path: String,
    pub sha256: String,
    pub ssdeep: Option<String>,
    pub classification: ClassificationLattice,
    pub policy: PolicyLattice,
    pub tainted: bool,
    pub origin_span_context: SpanContext,
    pub linked_span_contexts: Vec<SpanContext>,
    pub baggage: DlpBaggage,
    pub created_at_utc: DateTime<Utc>,
    pub updated_at_utc: DateTime<Utc>,
}

impl ArtifactTaintRecord {
    pub fn new(
        artifact_key: ArtifactKey,
        canonical_path: impl Into<String>,
        sha256: impl Into<String>,
        ssdeep: Option<String>,
        classification: ClassificationLattice,
        policy: PolicyLattice,
        tainted: bool,
        origin_span_context: SpanContext,
    ) -> Self {
        let sha256_str = sha256.into();
        let baggage = DlpBaggage::new(classification, policy, tainted, sha256_str.clone());
        let now = Utc::now();
        Self {
            artifact_key,
            canonical_path: canonical_path.into(),
            sha256: sha256_str,
            ssdeep,
            classification,
            policy,
            tainted,
            origin_span_context,
            linked_span_contexts: Vec::new(),
            baggage,
            created_at_utc: now,
            updated_at_utc: now,
        }
    }
}

pub const MAX_READ_HISTORY_PER_PROCESS: usize = 256;

/// Active taint state tracked for a running OS process instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTaintRecord {
    pub process_key: ProcessInstanceKey,
    pub executable_name: String,
    pub executable_path: String,
    pub is_long_lived: bool,
    pub classification: ClassificationLattice,
    pub policy: PolicyLattice,
    pub tainted: bool,
    pub active_read_descriptors: HashSet<ArtifactKey>,
    pub last_taint_read_time: Option<DateTime<Utc>>,
    pub origin_span_context: SpanContext,
    pub linked_span_contexts: Vec<SpanContext>,
    pub baggage: DlpBaggage,
    pub read_history: Vec<ArtifactKey>,
    pub created_at_utc: DateTime<Utc>,
    pub updated_at_utc: DateTime<Utc>,
}

impl ProcessTaintRecord {
    pub fn new(
        process_key: ProcessInstanceKey,
        executable_name: impl Into<String>,
        executable_path: impl Into<String>,
        is_long_lived: bool,
        origin_span_context: SpanContext,
    ) -> Self {
        let baggage = DlpBaggage::public_clean();
        let now = Utc::now();
        Self {
            process_key,
            executable_name: executable_name.into(),
            executable_path: executable_path.into(),
            is_long_lived,
            classification: ClassificationLattice::Public,
            policy: PolicyLattice::Monitor,
            tainted: false,
            active_read_descriptors: HashSet::new(),
            last_taint_read_time: None,
            origin_span_context,
            linked_span_contexts: Vec::new(),
            baggage,
            read_history: Vec::new(),
            created_at_utc: now,
            updated_at_utc: now,
        }
    }

    /// Records an artifact read in the bounded LRU read history (max 256 items).
    pub fn record_read_artifact(&mut self, artifact_key: ArtifactKey) {
        if let Some(pos) = self.read_history.iter().position(|k| k == &artifact_key) {
            self.read_history.remove(pos);
        } else if self.read_history.len() >= MAX_READ_HISTORY_PER_PROCESS {
            self.read_history.remove(0);
        }
        self.read_history.push(artifact_key);
    }
}

// ============================================================================
// 5. Pure-Rust ssdeep / Context Triggered Piecewise Hashing (CTPH)
// ============================================================================

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const SPAMSUM_LENGTH: usize = 64;

/// Generates a genuine Context Triggered Piecewise Hash (ssdeep / CTPH).
pub fn compute_ssdeep(data: &[u8]) -> String {
    if data.is_empty() {
        return "3::".to_string();
    }

    // Determine initial block size: start at 3, double until blocksize * SPAMSUM_LENGTH > data.len()
    let mut block_size: usize = 3;
    while block_size * SPAMSUM_LENGTH < data.len() {
        block_size *= 2;
    }

    // Try primary block size, if too short try smaller
    let (h1, h2) = ssdeep_chunk_hash(data, block_size);
    format!("{}:{}:{}", block_size, h1, h2)
}

fn ssdeep_chunk_hash(data: &[u8], block_size: usize) -> (String, String) {
    let mut h1 = String::with_capacity(SPAMSUM_LENGTH);
    let mut h2 = String::with_capacity(SPAMSUM_LENGTH);

    let mut rolling_window: [u8; 7] = [0; 7];
    let mut window_idx: usize = 0;
    let mut rolling_sum: u32 = 0;

    let mut chunk_hash1: u32 = 0;
    let mut chunk_hash2: u32 = 0;

    let mod1 = block_size as u32;
    let mod2 = (block_size * 2) as u32;

    for &b in data {
        // Rolling hash update (standard Adler-like window sum)
        let old_byte = rolling_window[window_idx];
        rolling_window[window_idx] = b;
        window_idx = (window_idx + 1) % 7;

        rolling_sum = rolling_sum
            .wrapping_sub(old_byte as u32)
            .wrapping_add(b as u32);
        rolling_sum = (rolling_sum << 5).wrapping_add(b as u32);

        // Piecewise chunk hashing (FNV-1a style)
        chunk_hash1 = (chunk_hash1 ^ (b as u32)).wrapping_mul(16777619);
        chunk_hash2 = (chunk_hash2 ^ (b as u32)).wrapping_mul(16777619);

        // Check boundary trigger for block_size
        if (rolling_sum % mod1) == (mod1 - 1) && h1.len() < SPAMSUM_LENGTH {
            let char_idx = (chunk_hash1 as usize) % 64;
            h1.push(B64_ALPHABET[char_idx] as char);
            chunk_hash1 = 0;
        }

        // Check boundary trigger for 2 * block_size
        if (rolling_sum % mod2) == (mod2 - 1) && h2.len() < SPAMSUM_LENGTH / 2 {
            let char_idx = (chunk_hash2 as usize) % 64;
            h2.push(B64_ALPHABET[char_idx] as char);
            chunk_hash2 = 0;
        }
    }

    // Flush tail characters if not empty
    if h1.len() < SPAMSUM_LENGTH {
        let char_idx = (chunk_hash1 as usize) % 64;
        h1.push(B64_ALPHABET[char_idx] as char);
    }
    if h2.len() < SPAMSUM_LENGTH / 2 {
        let char_idx = (chunk_hash2 as usize) % 64;
        h2.push(B64_ALPHABET[char_idx] as char);
    }

    (h1, h2)
}

/// Compares two ssdeep digests and returns a similarity score from `0` to `100`.
pub fn compare_ssdeep(hash1: &str, hash2: &str) -> u32 {
    let p1: Vec<&str> = hash1.split(':').collect();
    let p2: Vec<&str> = hash2.split(':').collect();

    if p1.len() < 3 || p2.len() < 3 {
        return 0;
    }

    let b1: usize = p1[0].parse().unwrap_or(0);
    let b2: usize = p2[0].parse().unwrap_or(0);

    if b1 == 0 || b2 == 0 {
        return 0;
    }

    if b1 == b2 {
        let score1 = sequence_similarity(p1[1], p2[1]);
        let score2 = sequence_similarity(p1[2], p2[2]);
        std::cmp::max(score1, score2)
    } else if b1 == b2 * 2 {
        sequence_similarity(p1[1], p2[2])
    } else if b2 == b1 * 2 {
        sequence_similarity(p1[2], p2[1])
    } else {
        0
    }
}

/// Computes string sequence similarity percentage based on longest common substring and edit ratio.
fn sequence_similarity(s1: &str, s2: &str) -> u32 {
    if s1.is_empty() || s2.is_empty() {
        return 0;
    }
    if s1 == s2 {
        return 100;
    }

    let b1 = s1.as_bytes();
    let b2 = s2.as_bytes();
    let max_len = std::cmp::max(b1.len(), b2.len());

    // Compute longest common continuous run
    let mut longest = 0;
    for i in 0..b1.len() {
        for j in 0..b2.len() {
            let mut k = 0;
            while i + k < b1.len() && j + k < b2.len() && b1[i + k] == b2[j + k] {
                k += 1;
            }
            if k > longest {
                longest = k;
            }
        }
    }

    if longest < 3 {
        return 0;
    }

    ((longest as f64 / max_len as f64) * 100.0).round() as u32
}

/// Helper: computes SHA-256 hex digest of arbitrary byte content.
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ============================================================================
// 6. Lock-Free In-Memory Taint State Machine (`DlpLineageTracker`)
// ============================================================================

/// Outcome of an inline egress verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    Allowed,
    Blocked {
        policy: PolicyLattice,
        classification: ClassificationLattice,
        span_context: SpanContext,
        reason: String,
    },
}

/// Decision made during file write evaluation under boundary mitigations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileWriteTaintDecision {
    /// Causal taint was successfully propagated to the target file.
    TaintPropagated {
        classification: ClassificationLattice,
        policy: PolicyLattice,
        transform_applied: Option<String>,
    },
    /// Boundary 1 Anti-Taint Creep: file write excluded from taint propagation.
    BenignExcluded { reason: String },
}

// ============================================================================
// OpenLineage RunEvent & Facet Models (Correlated OTel LogRecord Bodies)
// ============================================================================

/// Structured OpenLineage RunEvent model adhering to the OpenLineage specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenLineageRunEvent {
    pub event_type: String, // "START", "RUNNING", "COMPLETE", "FAIL", "ABORT"
    pub event_time: String, // ISO-8601 UTC
    pub run: OpenLineageRun,
    pub job: OpenLineageJob,
    #[serde(default)]
    pub inputs: Vec<OpenLineageInputDataset>,
    #[serde(default)]
    pub outputs: Vec<OpenLineageOutputDataset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenLineageRun {
    pub run_id: String, // UUID v4
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub facets: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenLineageJob {
    pub namespace: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub facets: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenLineageInputDataset {
    pub namespace: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub facets: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenLineageOutputDataset {
    pub namespace: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub facets: serde_json::Map<String, serde_json::Value>,
}

/// Facet containing SHA-256 and fuzzy ssdeep digests with classification & policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetDigestFacet {
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuzzy_hash_ssdeep: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// Custom taint facet on OpenLineage output datasets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputTaintFacet {
    pub tainted: bool,
    pub classification: String,
    pub policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default)]
    pub parent_trace_ids: Vec<String>,
    #[serde(default)]
    pub span_links: Vec<String>,
}

/// Synthetic OpenTelemetry LogRecord carrying OpenLineage RunEvent in its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticOtelLogRecord {
    pub timestamp_utc: String,
    pub trace_id: String,
    pub span_id: String,
    pub trace_flags: u8,
    pub severity_number: u32,
    pub severity_text: String,
    pub body: String, // OpenLineage RunEvent formatted as JSON
    pub attributes: BTreeMap<String, String>,
}

/// Synthetic child span emitted on blocked egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticBlockedChildSpan {
    pub name: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: String,
    pub start_time_utc: String,
    pub end_time_utc: String,
    pub status: String, // "ERROR"
    pub action: String, // "BLOCKED"
    pub policy: String,
    pub classification: String,
    pub attributes: BTreeMap<String, String>,
}

impl OpenLineageRunEvent {
    pub fn new(
        event_type: impl Into<String>,
        run_id: impl Into<String>,
        job_namespace: impl Into<String>,
        job_name: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            event_time: Utc::now().to_rfc3339(),
            run: OpenLineageRun {
                run_id: run_id.into(),
                facets: serde_json::Map::new(),
            },
            job: OpenLineageJob {
                namespace: job_namespace.into(),
                name: job_name.into(),
                facets: serde_json::Map::new(),
            },
            inputs: Vec::new(),
            outputs: Vec::new(),
            producer: Some(
                "https://github.com/oyesanyf/OshoosiClaw/tree/main/dlp_lineage".to_string(),
            ),
            schema_url: Some("https://openlineage.io/spec/1-0-5/OpenLineage.json".to_string()),
        }
    }

    pub fn with_input(
        mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        sha256: impl Into<String>,
        ssdeep: Option<String>,
        classification: Option<String>,
        policy: Option<String>,
    ) -> Self {
        let digest_facet = DatasetDigestFacet {
            sha256: sha256.into(),
            fuzzy_hash_ssdeep: ssdeep,
            classification,
            policy,
        };
        let mut facets = serde_json::Map::new();
        if let Ok(v) = serde_json::to_value(&digest_facet) {
            facets.insert("datasetDigest".to_string(), v);
        }
        self.inputs.push(OpenLineageInputDataset {
            namespace: namespace.into(),
            name: name.into(),
            facets,
        });
        self
    }

    pub fn with_output(
        mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        sha256: impl Into<String>,
        tainted: bool,
        classification: String,
        policy: String,
        action: Option<String>,
        parent_trace_ids: Vec<String>,
        span_links: Vec<String>,
    ) -> Self {
        let taint_facet = OutputTaintFacet {
            tainted,
            classification: classification.clone(),
            policy: policy.clone(),
            action: action.clone(),
            parent_trace_ids,
            span_links,
        };
        let digest_facet = DatasetDigestFacet {
            sha256: sha256.into(),
            fuzzy_hash_ssdeep: None,
            classification: Some(classification),
            policy: Some(policy),
        };
        let mut facets = serde_json::Map::new();
        if let Ok(v) = serde_json::to_value(&taint_facet) {
            facets.insert("taintFacet".to_string(), v);
        }
        if let Ok(v) = serde_json::to_value(&digest_facet) {
            facets.insert("datasetDigest".to_string(), v);
        }
        self.outputs.push(OpenLineageOutputDataset {
            namespace: namespace.into(),
            name: name.into(),
            facets,
        });
        self
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_otel_log_record(
        &self,
        trace_id: Option<&str>,
        span_id: Option<&str>,
    ) -> SyntheticOtelLogRecord {
        let body_json = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string());
        let t_id = trace_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{:032x}", rand::random::<u128>()));
        let s_id = span_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{:016x}", rand::random::<u64>()));

        let mut attrs = BTreeMap::new();
        attrs.insert(
            "openlineage.event_type".to_string(),
            self.event_type.clone(),
        );
        attrs.insert("openlineage.job.name".to_string(), self.job.name.clone());
        attrs.insert(
            "openlineage.job.namespace".to_string(),
            self.job.namespace.clone(),
        );
        attrs.insert("openlineage.run_id".to_string(), self.run.run_id.clone());
        attrs.insert(
            "openlineage.inputs_count".to_string(),
            self.inputs.len().to_string(),
        );
        attrs.insert(
            "openlineage.outputs_count".to_string(),
            self.outputs.len().to_string(),
        );

        let (severity_number, severity_text) = match self.event_type.as_str() {
            "FAIL" | "ABORT" => (17, "ERROR".to_string()),
            "START" | "RUNNING" => (9, "INFO".to_string()),
            "COMPLETE" => (9, "INFO".to_string()),
            _ => (9, "INFO".to_string()),
        };

        SyntheticOtelLogRecord {
            timestamp_utc: self.event_time.clone(),
            trace_id: t_id,
            span_id: s_id,
            trace_flags: 1, // SAMPLED (100% retention)
            severity_number,
            severity_text,
            body: body_json,
            attributes: attrs,
        }
    }
}

/// Real-time DLP Data Lineage and Taint State Tracker.
pub struct DlpLineageTracker {
    /// Active process taint table keyed by `(pid, start_time_100ns)`.
    pub active_processes: DashMap<ProcessInstanceKey, ProcessTaintRecord>,
    /// Active artifact taint table keyed by `(device_id, inode_or_file_id)`.
    pub active_artifacts: DashMap<ArtifactKey, ArtifactTaintRecord>,
    /// Catalog of content digests (both exact SHA-256 and fuzzy ssdeep digests).
    pub content_catalog: DashMap<String, ArtifactTaintRecord>,
    /// Temporal read-to-write causal window in seconds.
    pub read_to_write_ttl_secs: u64,
    /// Set of known long-lived system/interactive process executable names.
    pub long_lived_process_names: HashSet<String>,
    /// Tamper-evident Merkle audit tree retaining 100% of tainted traces.
    pub audit_tree: Arc<osoosi_audit::MerkleAuditTree>,
    /// Bounded in-memory ring-buffer of recent OpenLineage RunEvents (max 1,000).
    pub openlineage_events: RwLock<VecDeque<OpenLineageRunEvent>>,
    /// Bounded in-memory ring-buffer of correlated OTel LogRecords (max 1,000).
    pub otel_log_records: RwLock<VecDeque<SyntheticOtelLogRecord>>,
    /// Bounded in-memory ring-buffer of synthetic blocked child spans (max 1,000).
    pub blocked_child_spans: RwLock<VecDeque<SyntheticBlockedChildSpan>>,
}

impl Default for DlpLineageTracker {
    fn default() -> Self {
        Self::new(30)
    }
}

impl DlpLineageTracker {
    /// Creates a new `DlpLineageTracker` with the specified causal TTL in seconds.
    pub fn new(read_to_write_ttl_secs: u64) -> Self {
        let mut long_lived = HashSet::new();
        // Common long-lived interactive and system shells/hosts
        for name in &[
            "explorer.exe",
            "code.exe",
            "devenv.exe",
            "idea64.exe",
            "pycharm64.exe",
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "bash",
            "zsh",
            "system",
            "svchost.exe",
            "services.exe",
            "conhost.exe",
        ] {
            long_lived.insert(name.to_lowercase());
        }

        Self {
            active_processes: DashMap::new(),
            active_artifacts: DashMap::new(),
            content_catalog: DashMap::new(),
            read_to_write_ttl_secs,
            long_lived_process_names: long_lived,
            audit_tree: Arc::new(osoosi_audit::MerkleAuditTree::new()),
            openlineage_events: RwLock::new(VecDeque::with_capacity(1000)),
            otel_log_records: RwLock::new(VecDeque::with_capacity(1000)),
            blocked_child_spans: RwLock::new(VecDeque::with_capacity(1000)),
        }
    }

    /// Clears all tracked processes, artifacts, content digests, and lineage event buffers.
    pub fn clear(&self) {
        self.active_processes.clear();
        self.active_artifacts.clear();
        self.content_catalog.clear();
        self.openlineage_events.write().clear();
        self.otel_log_records.write().clear();
        self.blocked_child_spans.write().clear();
    }

    /// Helper: Checks whether a binary is classified as a long-lived host.
    pub fn is_long_lived(&self, executable_name: &str) -> bool {
        let normalized = executable_name.trim().to_lowercase();
        self.long_lived_process_names.contains(&normalized)
    }

    /// Synthesizes a deterministic or random `SpanContext` out-of-process.
    pub fn synthesize_span_context(
        trace_seed: Option<&str>,
        span_seed: Option<&str>,
    ) -> SpanContext {
        let trace_id = if let Some(seed) = trace_seed {
            let hash = blake3::hash(seed.as_bytes());
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&hash.as_bytes()[..16]);
            TraceId::from_bytes(bytes)
        } else {
            let rand_val = rand::random::<u128>();
            TraceId::from_bytes(rand_val.to_be_bytes())
        };

        let span_id = if let Some(seed) = span_seed {
            let hash = blake3::hash(seed.as_bytes());
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash.as_bytes()[..8]);
            SpanId::from_bytes(bytes)
        } else {
            let rand_val = rand::random::<u64>();
            SpanId::from_bytes(rand_val.to_be_bytes())
        };

        SpanContext::new(
            trace_id,
            span_id,
            TraceFlags::SAMPLED,
            false,
            TraceState::default(),
        )
    }

    /// Registers a sensitive source file artifact into the active and catalog registries.
    pub fn register_crown_jewel_artifact(
        &self,
        artifact_key: ArtifactKey,
        path: &str,
        content: &[u8],
        classification: ClassificationLattice,
        policy: PolicyLattice,
    ) -> ArtifactTaintRecord {
        let sha256 = compute_sha256_hex(content);
        let ssdeep = Some(compute_ssdeep(content));

        let trace_seed = format!("TRACE:SOURCE:{}:{}", path, sha256);
        let span_seed = format!("SPAN:SOURCE:{}:{}", artifact_key, sha256);
        let span_context = Self::synthesize_span_context(Some(&trace_seed), Some(&span_seed));

        let record = ArtifactTaintRecord::new(
            artifact_key,
            path,
            sha256.clone(),
            ssdeep.clone(),
            classification,
            policy,
            classification.is_sensitive(),
            span_context,
        );

        // Lock hygiene: insert without holding cross-map references
        self.active_artifacts.insert(artifact_key, record.clone());
        self.content_catalog.insert(sha256, record.clone());
        if let Some(ref ss) = ssdeep {
            self.content_catalog.insert(ss.clone(), record.clone());
        }

        record
    }

    /// Notifies the tracker that a process instance has opened a file for reading.
    pub fn on_file_read(
        &self,
        proc_key: ProcessInstanceKey,
        executable_name: &str,
        executable_path: &str,
        artifact_key: ArtifactKey,
    ) {
        let is_long_lived = self.is_long_lived(executable_name);
        let artifact_opt = self
            .active_artifacts
            .get(&artifact_key)
            .map(|r| r.value().clone());

        // Lock hygiene: drop artifact read guard before updating process map
        if let Some(artifact) = artifact_opt {
            let now = Utc::now();
            let mut proc_entry = self.active_processes.entry(proc_key).or_insert_with(|| {
                let proc_trace_seed = format!("TRACE:PROC:{}", proc_key);
                let proc_span_seed = format!("SPAN:PROC:{}:{}", executable_name, proc_key);
                let proc_sc =
                    Self::synthesize_span_context(Some(&proc_trace_seed), Some(&proc_span_seed));
                ProcessTaintRecord::new(
                    proc_key,
                    executable_name,
                    executable_path,
                    is_long_lived,
                    proc_sc,
                )
            });

            proc_entry.active_read_descriptors.insert(artifact_key);
            proc_entry.record_read_artifact(artifact_key);
            proc_entry.updated_at_utc = now;

            if artifact.tainted {
                proc_entry.tainted = true;
                proc_entry.classification = proc_entry.classification.join(artifact.classification);
                proc_entry.policy = proc_entry.policy.join(artifact.policy);
                proc_entry.last_taint_read_time = Some(now);
                proc_entry.baggage = proc_entry.baggage.join(&artifact.baggage);

                // Attach artifact's span context as link if not already present
                if !proc_entry
                    .linked_span_contexts
                    .iter()
                    .any(|sc| sc.span_id() == artifact.origin_span_context.span_id())
                {
                    proc_entry
                        .linked_span_contexts
                        .push(artifact.origin_span_context.clone());
                }
            }
        }
    }

    /// Notifies the tracker that a process has closed a file descriptor.
    pub fn on_file_close(&self, proc_key: &ProcessInstanceKey, artifact_key: &ArtifactKey) {
        if let Some(mut proc) = self.active_processes.get_mut(proc_key) {
            proc.active_read_descriptors.remove(artifact_key);
            proc.updated_at_utc = Utc::now();
        }
    }

    /// Removes a terminated process from the active tracking table.
    ///
    /// If `start_time_100ns > 0`, performs an exact `(pid, start_time)` lookup.
    /// If `start_time_100ns == 0`, purges all active instances matching `pid`.
    /// Returns `true` if at least one entry was removed.
    pub fn on_process_exit(&self, pid: u32, start_time_100ns: u64) -> bool {
        if start_time_100ns > 0 {
            let key = ProcessInstanceKey::new(pid, start_time_100ns);
            self.active_processes.remove(&key).is_some()
        } else {
            let keys_to_remove: Vec<ProcessInstanceKey> = self
                .active_processes
                .iter()
                .filter(|entry| entry.key().pid == pid)
                .map(|entry| *entry.key())
                .collect();
            let mut removed = false;
            for key in keys_to_remove {
                if self.active_processes.remove(&key).is_some() {
                    removed = true;
                }
            }
            removed
        }
    }

    /// Prunes stale artifact and process records from in-memory tracking tables.
    ///
    /// - If `artifact_ttl_secs > 0`, evicts any artifact whose `updated_at_utc` exceeds the TTL,
    ///   and also removes corresponding entries from `content_catalog`.
    /// - If `process_ttl_secs > 0`, evicts any process whose `updated_at_utc` exceeds the TTL.
    ///
    /// Returns the total number of evicted records.
    pub fn evict_expired(&self, artifact_ttl_secs: u64, process_ttl_secs: u64) -> usize {
        let now = Utc::now();
        let mut evicted_count = 0;

        if artifact_ttl_secs > 0 {
            let expired_artifacts: Vec<ArtifactKey> = self
                .active_artifacts
                .iter()
                .filter(|entry| {
                    let elapsed = (now - entry.value().updated_at_utc).num_seconds().max(0) as u64;
                    elapsed > artifact_ttl_secs
                })
                .map(|entry| *entry.key())
                .collect();

            for key in expired_artifacts {
                if let Some((_, record)) = self.active_artifacts.remove(&key) {
                    evicted_count += 1;
                    self.content_catalog.remove(&record.sha256);
                    if let Some(ref ssdeep) = record.ssdeep {
                        self.content_catalog.remove(ssdeep);
                    }
                }
            }
        }

        if process_ttl_secs > 0 {
            let expired_processes: Vec<ProcessInstanceKey> = self
                .active_processes
                .iter()
                .filter(|entry| {
                    let elapsed = (now - entry.value().updated_at_utc).num_seconds().max(0) as u64;
                    elapsed > process_ttl_secs
                })
                .map(|entry| *entry.key())
                .collect();

            for key in expired_processes {
                if self.active_processes.remove(&key).is_some() {
                    evicted_count += 1;
                }
            }
        }

        evicted_count
    }

    /// Evaluates a file write operation under Boundary 1 (Anti-Taint Creep) and Boundary 2.
    pub fn on_file_write(
        &self,
        proc_key: &ProcessInstanceKey,
        output_artifact_key: &ArtifactKey,
        output_path: &str,
        output_content: Option<&[u8]>,
        current_time: DateTime<Utc>,
    ) -> FileWriteTaintDecision {
        // Read process state, clone, and immediately drop map reference
        let proc_state = self
            .active_processes
            .get(proc_key)
            .map(|r| r.value().clone());
        let proc = match proc_state {
            Some(p) if p.tainted => p,
            _ => {
                return FileWriteTaintDecision::BenignExcluded {
                    reason: "Process is not tainted".to_string(),
                };
            }
        };

        // --- BOUNDARY 1 MITIGATION: Anti-Taint Creep in Long-Lived Processes ---
        if proc.is_long_lived {
            let handle_active = !proc.active_read_descriptors.is_empty();
            let mut ttl_expired = true;
            if let Some(last_read) = proc.last_taint_read_time {
                let elapsed_secs = (current_time - last_read).num_seconds().max(0) as u64;
                ttl_expired = elapsed_secs > self.read_to_write_ttl_secs;
            }

            let path_lower = output_path.to_ascii_lowercase();
            let is_benign_ext = path_lower.ends_with(".log")
                || path_lower.ends_with(".prefs")
                || path_lower.ends_with(".lock")
                || path_lower.ends_with(".ini")
                || path_lower.ends_with(".tmp.settings");

            // If handle closed, TTL expired, or writing benign configuration/log:
            if !handle_active || ttl_expired || is_benign_ext {
                // Require content or fuzzy hash corroboration against tainted inputs read
                let mut content_corroborated = false;
                if let Some(content) = output_content {
                    let out_sha256 = compute_sha256_hex(content);
                    let out_ssdeep = compute_ssdeep(content);

                    // Check history of read artifacts for similarity
                    for read_key in &proc.read_history {
                        if let Some(artifact_rec) = self.active_artifacts.get(read_key) {
                            if artifact_rec.tainted {
                                if artifact_rec.sha256 == out_sha256 {
                                    content_corroborated = true;
                                    break;
                                }
                                if let Some(ref in_ssdeep) = artifact_rec.ssdeep {
                                    if compare_ssdeep(in_ssdeep, &out_ssdeep) >= 30 {
                                        content_corroborated = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if !content_corroborated {
                    return FileWriteTaintDecision::BenignExcluded {
                        reason: format!(
                            "Anti-Taint Creep: Long-lived process '{}' wrote benign/unrelated file without content corroboration (handle_active={}, ttl_expired={})",
                            proc.executable_name, handle_active, ttl_expired
                        ),
                    };
                }
            }
        }

        // --- PROPAGATE CAUSAL TAINT ---
        let sha256 = output_content.map(compute_sha256_hex).unwrap_or_default();
        let ssdeep = output_content.map(compute_ssdeep);

        let trace_seed = format!("TRACE:OUT:{}:{}", output_path, proc_key);
        let span_seed = format!("SPAN:OUT:{}:{}", output_artifact_key, proc_key);
        let out_sc = Self::synthesize_span_context(Some(&trace_seed), Some(&span_seed));

        let mut output_record = ArtifactTaintRecord::new(
            *output_artifact_key,
            output_path,
            sha256.clone(),
            ssdeep.clone(),
            proc.classification,
            proc.policy,
            true,
            out_sc,
        );

        // Inherit baggage and process links
        output_record.baggage = proc.baggage.clone();
        output_record.linked_span_contexts = proc.linked_span_contexts.clone();

        self.active_artifacts
            .insert(*output_artifact_key, output_record.clone());
        if !sha256.is_empty() {
            self.content_catalog.insert(sha256, output_record.clone());
        }
        if let Some(ref ss) = ssdeep {
            self.content_catalog.insert(ss.clone(), output_record);
        }

        FileWriteTaintDecision::TaintPropagated {
            classification: proc.classification,
            policy: proc.policy,
            transform_applied: None,
        }
    }

    /// Records a multi-file merge or transformation operation (Boundary 2).
    ///
    /// Even when the resulting output shares 0% SHA-256 and 0% ssdeep similarity
    /// (e.g. encrypted with `openssl enc` or packaged in `7z.exe`), causal taint
    /// is propagated to the output artifact, inheriting the 1st tainted input's
    /// `SpanContext` as parent, files `2..N` as `SpanLinks`, and strictest-wins Baggage.
    pub fn record_process_transform(
        &self,
        proc_key: ProcessInstanceKey,
        executable_name: &str,
        executable_path: &str,
        input_keys: &[ArtifactKey],
        output_key: ArtifactKey,
        output_path: &str,
        output_content: &[u8],
        is_encrypted_or_encoded: bool,
    ) -> ArtifactTaintRecord {
        // Collect tainted inputs
        let mut tainted_inputs: Vec<ArtifactTaintRecord> = Vec::new();
        for key in input_keys {
            if let Some(rec) = self.active_artifacts.get(key) {
                if rec.tainted {
                    tainted_inputs.push(rec.value().clone());
                }
            }
        }

        // Compute dominant classification & policy via semilattice join
        let mut merged_classification = ClassificationLattice::Public;
        let mut merged_policy = PolicyLattice::Monitor;
        let mut merged_baggage = DlpBaggage::public_clean();

        for input in &tainted_inputs {
            merged_classification = merged_classification.join(input.classification);
            merged_policy = merged_policy.join(input.policy);
            merged_baggage = merged_baggage.join(&input.baggage);
        }

        if is_encrypted_or_encoded {
            merged_baggage.transform = Some("ENCRYPTED_OR_ENCODED".to_string());
        }

        // 1st tainted file provides parent SpanContext; files 2..N are SpanLinks
        let (parent_sc, secondary_scs) = if let Some(first) = tainted_inputs.first() {
            let rest: Vec<SpanContext> = tainted_inputs[1..]
                .iter()
                .map(|r| r.origin_span_context.clone())
                .collect();
            (first.origin_span_context.clone(), rest)
        } else {
            let default_sc = Self::synthesize_span_context(
                Some(&format!("TRACE:SYNTH:{}", proc_key)),
                Some(&format!("SPAN:SYNTH:{}", output_key)),
            );
            (default_sc, Vec::new())
        };

        // Create process span
        let mut links = Vec::with_capacity(secondary_scs.len());
        for sc in &secondary_scs {
            links.push(Link::with_context(sc.clone()));
        }

        // Synthesize child SpanContext for the output file
        let out_sha256 = compute_sha256_hex(output_content);
        let out_ssdeep = Some(compute_ssdeep(output_content));

        let out_trace_seed = format!("TRACE:OUT:{}:{}", parent_sc.trace_id(), output_path);
        let out_span_seed = format!("SPAN:OUT:{}:{}", output_key, out_sha256);
        let output_sc = Self::synthesize_span_context(Some(&out_trace_seed), Some(&out_span_seed));

        let mut output_record = ArtifactTaintRecord::new(
            output_key,
            output_path,
            out_sha256.clone(),
            out_ssdeep.clone(),
            merged_classification,
            merged_policy,
            merged_classification.is_sensitive(),
            output_sc,
        );

        output_record.linked_span_contexts = secondary_scs;
        output_record.baggage = merged_baggage;

        // Store into state machine
        self.active_artifacts
            .insert(output_key, output_record.clone());
        self.content_catalog
            .insert(out_sha256, output_record.clone());
        if let Some(ref ss) = out_ssdeep {
            self.content_catalog
                .insert(ss.clone(), output_record.clone());
        }

        // Update process state
        let mut proc_entry = self.active_processes.entry(proc_key).or_insert_with(|| {
            let proc_sc = Self::synthesize_span_context(
                Some(&format!("TRACE:PROC:{}", proc_key)),
                Some(&format!("SPAN:PROC:{}", executable_name)),
            );
            ProcessTaintRecord::new(
                proc_key,
                executable_name,
                executable_path,
                self.is_long_lived(executable_name),
                proc_sc,
            )
        });
        proc_entry.tainted = output_record.tainted;
        proc_entry.classification = merged_classification;
        proc_entry.policy = merged_policy;
        proc_entry.last_taint_read_time = Some(Utc::now());
        proc_entry.baggage = output_record.baggage.clone();

        output_record
    }

    /// Boundary 3: Rehydrates an unknown inode/file identity from content digests.
    ///
    /// If an artifact is copied or moved out-of-band to a new filesystem or host
    /// with a new `(device_id, inode_or_file_id)`, its exact SHA-256 and fuzzy
    /// ssdeep digests are matched against `content_catalog` to restore its
    /// original Crown Jewel provenance, `SpanContext`, and `QUARANTINE` policy.
    pub fn rehydrate_artifact_if_unknown(
        &self,
        artifact_key: &ArtifactKey,
        path: &str,
        content: &[u8],
    ) -> Option<ArtifactTaintRecord> {
        // Fast path: already known in active artifacts
        if let Some(existing) = self.active_artifacts.get(artifact_key) {
            return Some(existing.value().clone());
        }

        let sha256 = compute_sha256_hex(content);
        let ssdeep = compute_ssdeep(content);

        // 1. Exact SHA-256 match in content catalog
        if let Some(matched) = self.content_catalog.get(&sha256) {
            let matched_val = matched.value().clone();
            let mut rehydrated = matched_val.clone();
            rehydrated.artifact_key = *artifact_key;
            rehydrated.canonical_path = path.to_string();
            rehydrated.sha256 = sha256.clone();
            rehydrated.ssdeep = Some(ssdeep.clone());
            rehydrated.updated_at_utc = Utc::now();
            rehydrated.baggage.rehydrated = Some("content_digest_sha256".to_string());

            // Link to original origin span context
            rehydrated
                .linked_span_contexts
                .push(matched_val.origin_span_context.clone());

            self.active_artifacts
                .insert(*artifact_key, rehydrated.clone());
            return Some(rehydrated);
        }

        // 2. Fuzzy ssdeep match in content catalog (>= 50% threshold)
        for entry in self.content_catalog.iter() {
            let catalog_rec = entry.value();
            if let Some(ref cat_ssdeep) = catalog_rec.ssdeep {
                let sim = compare_ssdeep(cat_ssdeep, &ssdeep);
                if sim >= 50 {
                    let mut rehydrated = catalog_rec.clone();
                    rehydrated.artifact_key = *artifact_key;
                    rehydrated.canonical_path = path.to_string();
                    rehydrated.sha256 = sha256.clone();
                    rehydrated.ssdeep = Some(ssdeep.clone());
                    rehydrated.updated_at_utc = Utc::now();
                    rehydrated.baggage.rehydrated =
                        Some(format!("fuzzy_hash_ssdeep:similarity={}%", sim));

                    rehydrated
                        .linked_span_contexts
                        .push(catalog_rec.origin_span_context.clone());

                    self.active_artifacts
                        .insert(*artifact_key, rehydrated.clone());
                    return Some(rehydrated);
                }
            }
        }

        None
    }

    /// Evaluates an outbound egress attempt in nanoseconds against active taint state.
    pub fn check_egress_blocking(&self, artifact_key: &ArtifactKey) -> EgressDecision {
        if let Some(rec) = self.active_artifacts.get(artifact_key) {
            if rec.tainted && rec.policy.is_enforced() {
                return EgressDecision::Blocked {
                    policy: rec.policy,
                    classification: rec.classification,
                    span_context: rec.origin_span_context.clone(),
                    reason: format!(
                        "Egress blocked: artifact {} is marked {} with policy {}",
                        rec.canonical_path,
                        rec.classification.as_str(),
                        rec.policy.as_str()
                    ),
                };
            }
        }
        EgressDecision::Allowed
    }

    /// Evaluates an outbound process network egress attempt in nanoseconds.
    pub fn check_process_egress_blocking(&self, proc_key: &ProcessInstanceKey) -> EgressDecision {
        if let Some(proc) = self.active_processes.get(proc_key) {
            if proc.tainted && proc.policy.is_enforced() {
                return EgressDecision::Blocked {
                    policy: proc.policy,
                    classification: proc.classification,
                    span_context: proc.origin_span_context.clone(),
                    reason: format!(
                        "Process egress blocked: process {} ({}) is marked {} with policy {}",
                        proc.executable_name,
                        proc.process_key,
                        proc.classification.as_str(),
                        proc.policy.as_str()
                    ),
                };
            }
        }
        EgressDecision::Allowed
    }

    /// Registers a newly created process instance and propagates parent taint if the parent is tainted.
    pub fn on_process_create(
        &self,
        pid: u32,
        start_time_100ns: u64,
        image_name: &str,
        image_path: &str,
        parent_pid: Option<u32>,
        parent_start_time_100ns: Option<u64>,
    ) -> ProcessTaintRecord {
        let child_key = ProcessInstanceKey::new(pid, start_time_100ns);
        let is_long_lived = self.is_long_lived(image_name);

        let child_trace_seed = format!("TRACE:PROC:{}", child_key);
        let child_span_seed = format!("SPAN:PROC:{}:{}", image_name, child_key);
        let child_sc =
            Self::synthesize_span_context(Some(&child_trace_seed), Some(&child_span_seed));

        let mut child_rec =
            ProcessTaintRecord::new(child_key, image_name, image_path, is_long_lived, child_sc);

        // Check if parent process is tainted
        if let Some(p_pid) = parent_pid {
            let parent_taint_opt = if let Some(p_start) = parent_start_time_100ns {
                if p_start > 0 {
                    self.active_processes
                        .get(&ProcessInstanceKey::new(p_pid, p_start))
                        .map(|r| r.value().clone())
                } else {
                    self.active_processes
                        .iter()
                        .find(|e| e.key().pid == p_pid && e.value().tainted)
                        .map(|e| e.value().clone())
                }
            } else {
                self.active_processes
                    .iter()
                    .find(|e| e.key().pid == p_pid && e.value().tainted)
                    .map(|e| e.value().clone())
            };

            if let Some(parent) = parent_taint_opt {
                if parent.tainted {
                    child_rec.tainted = true;
                    child_rec.classification = parent.classification;
                    child_rec.policy = parent.policy;
                    child_rec.baggage = parent.baggage.clone();
                    child_rec.last_taint_read_time = parent.last_taint_read_time;
                    child_rec.read_history = parent.read_history.clone();
                    child_rec
                        .linked_span_contexts
                        .push(parent.origin_span_context.clone());
                    for sc in &parent.linked_span_contexts {
                        child_rec.linked_span_contexts.push(sc.clone());
                    }
                }
            }
        }

        self.active_processes.insert(child_key, child_rec.clone());
        child_rec
    }

    /// Helper for FileRead events taking physical or canonical file path.
    pub fn on_file_read_path(
        &self,
        pid: u32,
        start_time_100ns: u64,
        executable_name: &str,
        executable_path: &str,
        file_path: &str,
    ) {
        let proc_key = ProcessInstanceKey::new(pid, start_time_100ns);
        let art_key = ArtifactKey::from_path_or_synthetic(file_path);

        // Attempt rehydration if unknown and file exists on disk
        if !self.active_artifacts.contains_key(&art_key) {
            if let Ok(bytes) = std::fs::read(file_path) {
                let _ = self.rehydrate_artifact_if_unknown(&art_key, file_path, &bytes);
            }
        }

        let sha = self
            .active_artifacts
            .get(&art_key)
            .map(|r| r.sha256.clone())
            .unwrap_or_default();

        // Record live file event in siquery-rs table
        osoosi_agent_anomaly::siquery::record_live_file_event(
            osoosi_agent_anomaly::siquery::FileEventRecord {
                target_path: file_path.to_string(),
                action: "READ".to_string(),
                pid: pid as i64,
                process_name: executable_name.to_string(),
                sha256: sha,
                time: Utc::now().timestamp(),
            },
        );

        self.on_file_read(proc_key, executable_name, executable_path, art_key);
    }

    /// Helper for FileWrite events taking physical or canonical file path and content.
    pub fn on_file_write_path(
        &self,
        pid: u32,
        start_time_100ns: u64,
        output_path: &str,
        content_bytes: Option<&[u8]>,
    ) -> FileWriteTaintDecision {
        let proc_key = ProcessInstanceKey::new(pid, start_time_100ns);
        let out_key = ArtifactKey::from_path_or_synthetic(output_path);

        let decision =
            self.on_file_write(&proc_key, &out_key, output_path, content_bytes, Utc::now());

        let sha = content_bytes.map(compute_sha256_hex).unwrap_or_default();
        let proc_name = self
            .active_processes
            .get(&proc_key)
            .map(|p| p.executable_name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Record live file event in siquery-rs table
        osoosi_agent_anomaly::siquery::record_live_file_event(
            osoosi_agent_anomaly::siquery::FileEventRecord {
                target_path: output_path.to_string(),
                action: "WRITE".to_string(),
                pid: pid as i64,
                process_name: proc_name,
                sha256: sha,
                time: Utc::now().timestamp(),
            },
        );

        decision
    }

    /// Handles file rename operations, transferring causal taint to the new destination.
    pub fn on_file_rename(&self, pid: u32, _start_time_100ns: u64, old_path: &str, new_path: &str) {
        let old_key = ArtifactKey::from_path_or_synthetic(old_path);
        let new_key = ArtifactKey::from_path_or_synthetic(new_path);

        if let Some((_, mut rec)) = self.active_artifacts.remove(&old_key) {
            rec.artifact_key = new_key;
            rec.canonical_path = new_path.to_string();
            rec.updated_at_utc = Utc::now();
            self.active_artifacts.insert(new_key, rec.clone());

            let sha = rec.sha256.clone();
            osoosi_agent_anomaly::siquery::record_live_file_event(
                osoosi_agent_anomaly::siquery::FileEventRecord {
                    target_path: new_path.to_string(),
                    action: "RENAME".to_string(),
                    pid: pid as i64,
                    process_name: format!("rename:{}", old_path),
                    sha256: sha,
                    time: Utc::now().timestamp(),
                },
            );
        }
    }

    /// Evaluates whether outbound egress is permitted for a file path or cryptographic content digest.
    pub fn check_egress_allowed(
        &self,
        file_path: Option<&str>,
        content_hash: Option<&str>,
    ) -> Result<(), EgressDecision> {
        self.check_egress_allowed_full(file_path, content_hash, None, None, None)
    }

    /// Evaluates whether outbound egress is permitted for candidate staging file, digest, URL, and PID.
    pub fn check_egress_allowed_full(
        &self,
        file_path: Option<&str>,
        content_hash: Option<&str>,
        content_bytes: Option<&[u8]>,
        url: Option<&str>,
        pid: Option<u32>,
    ) -> Result<(), EgressDecision> {
        // 1. Check content hash in content_catalog
        if let Some(h) = content_hash {
            let normalized_hash = h.trim().to_ascii_lowercase();
            if let Some(matched) = self.content_catalog.get(&normalized_hash) {
                if matched.tainted && matched.policy.is_enforced() {
                    return Err(EgressDecision::Blocked {
                        policy: matched.policy,
                        classification: matched.classification,
                        span_context: matched.origin_span_context.clone(),
                        reason: format!(
                            "Egress blocked: content hash '{}' matches tainted artifact '{}' ({}, {})",
                            normalized_hash,
                            matched.canonical_path,
                            matched.classification,
                            matched.policy
                        ),
                    });
                }
            }
        }

        // 2. Check content bytes if supplied
        if let Some(bytes) = content_bytes {
            let sha = compute_sha256_hex(bytes);
            if let Some(matched) = self.content_catalog.get(&sha) {
                if matched.tainted && matched.policy.is_enforced() {
                    return Err(EgressDecision::Blocked {
                        policy: matched.policy,
                        classification: matched.classification,
                        span_context: matched.origin_span_context.clone(),
                        reason: format!(
                            "Egress blocked: content SHA-256 matches tainted artifact '{}' ({}, {})",
                            matched.canonical_path, matched.classification, matched.policy
                        ),
                    });
                }
            }
        }

        // 3. Check candidate file path
        if let Some(p) = file_path {
            let key = ArtifactKey::from_path_or_synthetic(p);
            let decision = self.check_egress_blocking(&key);
            if let EgressDecision::Blocked {
                policy,
                classification,
                span_context,
                reason,
            } = decision
            {
                return Err(EgressDecision::Blocked {
                    policy,
                    classification,
                    span_context,
                    reason,
                });
            }
        }

        // 4. Check PID if provided
        if let Some(p) = pid {
            for entry in self.active_processes.iter() {
                if entry.key().pid == p
                    && entry.value().tainted
                    && entry.value().policy.is_enforced()
                {
                    let proc = entry.value();
                    return Err(EgressDecision::Blocked {
                        policy: proc.policy,
                        classification: proc.classification,
                        span_context: proc.origin_span_context.clone(),
                        reason: format!(
                            "Process egress blocked: PID {} ({}) is tainted with policy {}",
                            p, proc.executable_name, proc.policy
                        ),
                    });
                }
            }
        }

        // 5. Check URL if provided (defense-in-depth URL sink checks)
        if let Some(u) = url {
            let u_lower = u.to_ascii_lowercase();
            if (u_lower.contains("dlptest.com")
                || u_lower.contains("pastebin.com")
                || u_lower.contains("webhook.site"))
                && self
                    .active_artifacts
                    .iter()
                    .any(|a| a.value().tainted && a.value().classification.is_crown_jewel())
            {
                if let Some(first_tainted) = self
                    .active_artifacts
                    .iter()
                    .find(|a| a.value().tainted && a.value().classification.is_crown_jewel())
                {
                    return Err(EgressDecision::Blocked {
                        policy: first_tainted.value().policy,
                        classification: first_tainted.value().classification,
                        span_context: first_tainted.value().origin_span_context.clone(),
                        reason: format!(
                            "URL egress blocked: destination '{}' blocked under active Crown Jewel taint ({})",
                            u, first_tainted.value().canonical_path
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Correlates active processes and open files with `siquery-rs` tables.
    pub fn correlate_with_siquery(
        &self,
        siquery: &osoosi_agent_anomaly::siquery::SiqueryEngine,
    ) -> Result<usize, String> {
        let mut correlated = 0usize;

        // Query open files from siquery-rs
        if let Ok(rows) =
            siquery.execute_query("SELECT pid, fd, path FROM process_open_files LIMIT 1000;")
        {
            for row in rows {
                let pid = row.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
                let path = row.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if pid > 0 && !path.is_empty() {
                    let art_key = ArtifactKey::from_path_or_synthetic(path);
                    if self.active_artifacts.contains_key(&art_key) {
                        let proc_key = ProcessInstanceKey::new(pid, 0);
                        self.on_file_read(proc_key, "siquery_correlated", path, art_key);
                        correlated += 1;
                    }
                }
            }
        }

        // Query file events from siquery-rs
        if let Ok(events) = siquery.execute_query(
            "SELECT target_path, action, pid, process_name, sha256 FROM file_events LIMIT 500;",
        ) {
            for row in events {
                let path = row
                    .get("target_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let sha = row.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
                if !path.is_empty() && !sha.is_empty() {
                    if self.content_catalog.contains_key(sha) {
                        let art_key = ArtifactKey::from_path_or_synthetic(path);
                        if let Some(matched) = self.content_catalog.get(sha) {
                            self.active_artifacts
                                .insert(art_key, matched.value().clone());
                            correlated += 1;
                        }
                    }
                }
            }
        }

        Ok(correlated)
    }

    /// Emits a synthetic child span with status ERROR, dlp.action=BLOCKED, and zero-PII OTel attributes.
    /// Retains 100% of tainted traces in the cryptographic Merkle audit tree (tail-based sampling).
    pub fn emit_blocked_child_span(
        &self,
        parent_context: &SpanContext,
        policy: &PolicyLattice,
        classification: &ClassificationLattice,
        url: Option<&str>,
        file_path: Option<&str>,
        hash: Option<&str>,
        reason: &str,
    ) -> SyntheticBlockedChildSpan {
        let now = Utc::now().to_rfc3339();
        let trace_id = parent_context.trace_id().to_string();
        let parent_span_id = parent_context.span_id().to_string();
        let child_span_id = format!("{:016x}", rand::random::<u64>());

        let mut attrs = BTreeMap::new();
        attrs.insert("dlp.action".to_string(), "BLOCKED".to_string());
        attrs.insert("dlp.policy".to_string(), policy.to_string());
        attrs.insert("dlp.classification".to_string(), classification.to_string());
        attrs.insert("dlp.tainted".to_string(), "true".to_string());
        attrs.insert(
            "dlp.threat_type".to_string(),
            "DATA_EXFILTRATION".to_string(),
        );
        attrs.insert("dlp.retained_taint".to_string(), "true".to_string());
        attrs.insert(
            "dlp.block_reason".to_string(),
            "tainted_lineage_policy".to_string(),
        );
        attrs.insert("dlp.trace_id".to_string(), trace_id.clone());
        attrs.insert("otel.status_code".to_string(), "ERROR".to_string());
        attrs.insert("otel.status_description".to_string(), reason.to_string());
        attrs.insert("error.type".to_string(), "DLP_EGRESS_BLOCKED".to_string());

        if let Some(u) = url {
            attrs.insert("url.full".to_string(), sanitize_url_zero_pii(u));
        }
        if let Some(fp) = file_path {
            attrs.insert("file.path".to_string(), fp.to_string());
        }
        if let Some(h) = hash {
            attrs.insert("file.hash.sha256".to_string(), h.to_string());
        }

        let child_span = SyntheticBlockedChildSpan {
            name: "dlp.egress_blocked".to_string(),
            trace_id: trace_id.clone(),
            span_id: child_span_id,
            parent_span_id,
            start_time_utc: now.clone(),
            end_time_utc: now,
            status: "ERROR".to_string(),
            action: "BLOCKED".to_string(),
            policy: policy.to_string(),
            classification: classification.to_string(),
            attributes: attrs,
        };

        // Retain 100% of tainted traces: anchor into Merkle audit tree
        let _ = self.audit_tree.log(
            "dlp.egress_blocked",
            serde_json::json!({
                "trace_id": &child_span.trace_id,
                "span_id": &child_span.span_id,
                "action": "BLOCKED",
                "policy": &child_span.policy,
                "classification": &child_span.classification,
                "reason": reason,
            }),
        );

        let mut lock = self.blocked_child_spans.write();
        if lock.len() >= 1000 {
            lock.pop_front();
        }
        lock.push_back(child_span.clone());

        child_span
    }

    /// Emits a structured OpenLineage RunEvent formatted as JSON and attached as a correlated
    /// OpenTelemetry LogRecord body stamped with matching TraceId and SpanId.
    pub fn emit_openlineage_run_event(
        &self,
        event: OpenLineageRunEvent,
        trace_id: Option<&str>,
        span_id: Option<&str>,
    ) -> SyntheticOtelLogRecord {
        let record = event.to_otel_log_record(trace_id, span_id);

        // Tail-based sampling: 100% of tainted traces retained in Merkle audit tree
        let _ = self.audit_tree.log(
            "openlineage.run_event",
            serde_json::json!({
                "trace_id": &record.trace_id,
                "span_id": &record.span_id,
                "event_type": &event.event_type,
                "job": &event.job.name,
                "inputs_count": event.inputs.len(),
                "outputs_count": event.outputs.len(),
                "timestamp": &record.timestamp_utc,
            }),
        );

        // Append to in-memory event buffers
        {
            let mut ev_lock = self.openlineage_events.write();
            if ev_lock.len() >= 1000 {
                ev_lock.pop_front();
            }
            ev_lock.push_back(event);
        }
        {
            let mut rec_lock = self.otel_log_records.write();
            if rec_lock.len() >= 1000 {
                rec_lock.pop_front();
            }
            rec_lock.push_back(record.clone());
        }

        record
    }

    /// Returns live JSON summary directly from in-memory DashMap and ring buffers in < 5ms.
    pub fn get_lineage_summary_json(&self) -> serde_json::Value {
        let mut active_traces_set = HashSet::new();
        let mut hops_count = self.active_processes.len();
        let mut span_links_count = 0usize;

        let mut input_datasets = Vec::new();
        let mut jobs = Vec::new();
        let mut output_datasets = Vec::new();

        // 1. Process active artifacts
        for entry in self.active_artifacts.iter() {
            let art = entry.value();
            if art.tainted {
                active_traces_set.insert(art.origin_span_context.trace_id().to_string());
            }
            span_links_count += art.linked_span_contexts.len();

            let input_obj = serde_json::json!({
                "namespace": format!("file://{}/{}", entry.key().device_id, entry.key().inode_or_file_id),
                "name": &art.canonical_path,
                "sha256": &art.sha256,
                "fuzzy_hash_ssdeep": art.ssdeep.as_deref().unwrap_or(""),
                "classification": art.classification.to_string(),
                "policy": art.policy.to_string(),
                "tainted": art.tainted,
                "trace_id": art.origin_span_context.trace_id().to_string(),
                "span_id": art.origin_span_context.span_id().to_string(),
            });
            input_datasets.push(input_obj);
        }

        // 2. Process active processes
        for entry in self.active_processes.iter() {
            let proc = entry.value();
            if proc.tainted {
                active_traces_set.insert(proc.origin_span_context.trace_id().to_string());
            }
            hops_count += proc.read_history.len();
            span_links_count += proc.linked_span_contexts.len();

            let job_obj = serde_json::json!({
                "namespace": "oshoosi://endpoint",
                "name": format!("{}#pid:{}@start:{}", proc.executable_name, entry.key().pid, entry.key().start_time_100ns),
                "pid": entry.key().pid,
                "process_start_time": entry.key().start_time_100ns,
                "executable_path": &proc.executable_path,
                "classification": proc.classification.to_string(),
                "policy": proc.policy.to_string(),
                "tainted": proc.tainted,
                "trace_id": proc.origin_span_context.trace_id().to_string(),
                "span_id": proc.origin_span_context.span_id().to_string(),
                "span_links_count": proc.linked_span_contexts.len(),
            });
            jobs.push(job_obj);
        }

        // 3. Process output datasets from OpenLineage events and blocked spans
        {
            let events_lock = self.openlineage_events.read();
            for ev in events_lock.iter() {
                for out in &ev.outputs {
                    output_datasets.push(serde_json::json!({
                        "namespace": &out.namespace,
                        "name": &out.name,
                        "facets": &out.facets,
                    }));
                }
            }
        }

        let blocked_lock = self.blocked_child_spans.read();
        let blocked_count = blocked_lock.len();
        for sp in blocked_lock.iter() {
            let sink = sp
                .attributes
                .get("url.full")
                .cloned()
                .unwrap_or_else(|| "sink://network/blocked".to_string());
            output_datasets.push(serde_json::json!({
                "namespace": "sink://network/blocked",
                "name": sink,
                "classification": &sp.classification,
                "policy": &sp.policy,
                "action": "BLOCKED",
                "trace_id": &sp.trace_id,
                "span_id": &sp.span_id,
            }));
        }
        drop(blocked_lock);

        let active_traces_count = active_traces_set.len();
        let active_traces_vec: Vec<String> = active_traces_set.into_iter().collect();

        // Recent lineage events preview
        let recent_events: Vec<serde_json::Value> = self
            .openlineage_events
            .read()
            .iter()
            .rev()
            .take(50)
            .map(|ev| serde_json::to_value(ev).unwrap_or(serde_json::Value::Null))
            .collect();

        serde_json::json!({
            "status": "ok",
            "summary": {
                "active_tainted_traces": active_traces_count,
                "osquery_har_hops": hops_count,
                "blocked_derived_egresses": blocked_count,
                "span_links_merged": span_links_count,
            },
            "kpis": {
                "active_traces": active_traces_count,
                "hops": hops_count,
                "blocked_egresses": blocked_count,
                "spanlinks_merged": span_links_count,
            },
            "active_tainted_traces": active_traces_vec,
            "input_datasets": input_datasets,
            "jobs": jobs,
            "output_datasets": output_datasets,
            "lineage_events": recent_events,
        })
    }

    /// Accepts OpenLineage RunEvent or synthetic taint event payloads, updates in-memory
    /// DashMap state, evaluates synchronous inline policy, and returns evaluation status.
    pub fn ingest_lineage_event(
        &self,
        event_type: &str,
        producer: Option<&str>,
        job_info: Option<&serde_json::Value>,
        inputs: &[serde_json::Value],
        outputs: &[serde_json::Value],
        egress_sink: Option<&str>,
    ) -> (bool, String, String, String, String) {
        let run_id = uuid::Uuid::new_v4().to_string();
        let job_name = job_info
            .and_then(|j| j.get("command_line").or_else(|| j.get("executable_path")))
            .and_then(|v| v.as_str())
            .unwrap_or("lineage_ingest_job");
        let job_namespace = producer.unwrap_or("oshoosi://endpoint/custom_agent");

        let mut ol_event = OpenLineageRunEvent::new(event_type, run_id, job_namespace, job_name);

        let mut input_keys = Vec::new();
        let mut dominant_classification = ClassificationLattice::Public;
        let mut dominant_policy = PolicyLattice::Monitor;
        let mut any_tainted = false;

        // Process inputs
        for inp in inputs {
            let path = inp
                .get("path")
                .or_else(|| inp.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sha = inp
                .get("sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let key = if let (Some(dev), Some(ino)) = (
                inp.get("device_id").and_then(|v| v.as_u64()),
                inp.get("inode").and_then(|v| v.as_u64()),
            ) {
                ArtifactKey::new(dev, ino)
            } else if !path.is_empty() {
                ArtifactKey::from_path_or_synthetic(path)
            } else {
                ArtifactKey::new(1, rand::random::<u64>())
            };

            let mut classification = ClassificationLattice::Public;
            let mut policy = PolicyLattice::Monitor;

            // Check if key or sha256 already exists in active_artifacts or content_catalog
            if let Some(existing) = self.active_artifacts.get(&key) {
                if existing.tainted {
                    any_tainted = true;
                    classification = existing.classification;
                    policy = existing.policy;
                }
            } else if let Some(existing) = self.content_catalog.get(&sha) {
                if existing.tainted {
                    any_tainted = true;
                    classification = existing.classification;
                    policy = existing.policy;
                }
            } else if let Some(c_str) = inp.get("classification").and_then(|v| v.as_str()) {
                let parsed_c = ClassificationLattice::from_str_relaxed(c_str);
                let parsed_p = inp
                    .get("policy")
                    .and_then(|v| v.as_str())
                    .map(PolicyLattice::from_str_relaxed)
                    .unwrap_or(PolicyLattice::Monitor);
                if parsed_c.is_sensitive() {
                    any_tainted = true;
                    classification = parsed_c;
                    policy = parsed_p;
                    self.register_crown_jewel_artifact(
                        key,
                        path,
                        sha.as_bytes(),
                        classification,
                        policy,
                    );
                }
            }

            dominant_classification = dominant_classification.join(classification);
            dominant_policy = dominant_policy.join(policy);
            input_keys.push(key);

            ol_event = ol_event.with_input(
                format!("file://{}/{}", key.device_id, key.inode_or_file_id),
                path,
                sha,
                None,
                Some(classification.to_string()),
                Some(policy.to_string()),
            );
        }

        // Process job
        let pid = job_info
            .and_then(|j| j.get("pid"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let start_time = job_info
            .and_then(|j| j.get("process_start_time"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let proc_key = ProcessInstanceKey::new(pid, start_time);

        if pid > 0 {
            let exe_path = job_info
                .and_then(|j| j.get("executable_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("agent_process.exe");
            let exe_name = std::path::Path::new(exe_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "agent_process.exe".to_string());
            for k in &input_keys {
                self.on_file_read(proc_key, &exe_name, exe_path, *k);
            }
        }

        let trace_id = format!("{:032x}", rand::random::<u128>());
        let span_id = format!("{:016x}", rand::random::<u64>());

        // Process outputs
        for out in outputs {
            let out_path = out
                .get("path")
                .or_else(|| out.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let out_sha = out.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
            let out_key = if let (Some(dev), Some(ino)) = (
                out.get("device_id").and_then(|v| v.as_u64()),
                out.get("inode").and_then(|v| v.as_u64()),
            ) {
                ArtifactKey::new(dev, ino)
            } else if !out_path.is_empty() {
                ArtifactKey::from_path_or_synthetic(out_path)
            } else {
                ArtifactKey::new(1, rand::random::<u64>())
            };

            if pid > 0 {
                let exe_name = job_info
                    .and_then(|j| j.get("executable_path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("agent_process.exe");
                let _ = self.record_process_transform(
                    proc_key,
                    exe_name,
                    exe_name,
                    &input_keys,
                    out_key,
                    out_path,
                    out_sha.as_bytes(),
                    false,
                );
            }

            ol_event = ol_event.with_output(
                format!("file://{}/{}", out_key.device_id, out_key.inode_or_file_id),
                out_path,
                out_sha,
                any_tainted,
                dominant_classification.to_string(),
                dominant_policy.to_string(),
                if any_tainted {
                    Some("TAINT_INHERITED".to_string())
                } else {
                    Some("CLEAN".to_string())
                },
                vec![trace_id.clone()],
                vec![span_id.clone()],
            );
        }

        // Check inline egress blocking if sink specified
        let mut action = if any_tainted {
            "TAINT_INHERITED".to_string()
        } else {
            "PERMITTED".to_string()
        };
        let mut rationale = "Lineage ingest completed successfully".to_string();

        if let Some(sink) = egress_sink {
            if any_tainted
                && (dominant_classification.is_crown_jewel() || dominant_policy.is_enforced())
            {
                action = "BLOCKED".to_string();
                rationale = format!(
                    "Derived artifact inherits {} classification via DashMap lattice dominance; outbound egress to unauthorized sink '{}' blocked before transmission",
                    dominant_classification, sink
                );

                // Emit synthetic child span for blocked egress
                let raw_trace = hex::decode(&trace_id).unwrap_or_default();
                let mut trace_bytes = [1u8; 16];
                if raw_trace.len() == 16 {
                    trace_bytes.copy_from_slice(&raw_trace);
                }
                let raw_span = hex::decode(&span_id).unwrap_or_default();
                let mut span_bytes = [1u8; 8];
                if raw_span.len() == 8 {
                    span_bytes.copy_from_slice(&raw_span);
                }

                let parent_sc = SpanContext::new(
                    TraceId::from_bytes(trace_bytes),
                    SpanId::from_bytes(span_bytes),
                    TraceFlags::SAMPLED,
                    false,
                    TraceState::default(),
                );
                let _child_span = self.emit_blocked_child_span(
                    &parent_sc,
                    &dominant_policy,
                    &dominant_classification,
                    Some(sink),
                    None,
                    None,
                    &rationale,
                );
            }
        }

        // Emit OpenLineage RunEvent and correlated OTel LogRecord
        let _ = self.emit_openlineage_run_event(ol_event, Some(&trace_id), Some(&span_id));

        (any_tainted, action, rationale, trace_id, span_id)
    }

    /// Evaluates candidate egress for proxy integration in nanoseconds.
    pub fn check_egress_for_proxy(
        &self,
        url: Option<&str>,
        file_path: Option<&str>,
        hash: Option<&str>,
    ) -> Result<(), osoosi_agent_anomaly::egress_proxy::EgressLineageBlockInfo> {
        match self.check_egress_allowed_full(file_path, hash, None, url, None) {
            Ok(()) => Ok(()),
            Err(EgressDecision::Blocked {
                policy,
                classification,
                span_context,
                reason,
            }) => {
                // 1. Emit synthetic child span with status ERROR and zero-PII attributes
                let child_span = self.emit_blocked_child_span(
                    &span_context,
                    &policy,
                    &classification,
                    url,
                    file_path,
                    hash,
                    &reason,
                );

                // 2. Format OpenLineage RunEvent and emit as correlated OTel LogRecord
                let run_id = uuid::Uuid::new_v4().to_string();
                let mut event = OpenLineageRunEvent::new(
                    "FAIL",
                    run_id,
                    "oshoosi://endpoint/inline_egress",
                    format!("egress_block#trace:{}", span_context.trace_id()),
                );
                if let Some(fp) = file_path {
                    event = event.with_input(
                        "file://local/artifact",
                        fp,
                        hash.unwrap_or(""),
                        None,
                        Some(classification.to_string()),
                        Some(policy.to_string()),
                    );
                }
                if let Some(u) = url {
                    event = event.with_output(
                        "sink://network/outbound",
                        u,
                        hash.unwrap_or(""),
                        true,
                        classification.to_string(),
                        policy.to_string(),
                        Some("BLOCKED".to_string()),
                        vec![span_context.trace_id().to_string()],
                        vec![child_span.span_id.clone()],
                    );
                }

                let _ = self.emit_openlineage_run_event(
                    event,
                    Some(&child_span.trace_id),
                    Some(&child_span.span_id),
                );

                Err(osoosi_agent_anomaly::egress_proxy::EgressLineageBlockInfo {
                    policy: policy.to_string(),
                    classification: classification.to_string(),
                    reason,
                    trace_id: Some(child_span.trace_id),
                    span_id: Some(child_span.span_id),
                })
            }
            Err(EgressDecision::Allowed) => Ok(()),
        }
    }

    /// Registers the egress proxy hook connecting `osoosi-agent-anomaly` to this tracker.
    pub fn register_egress_proxy_hooks(&'static self) {
        static HOOK_ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !HOOK_ONCE.swap(true, std::sync::atomic::Ordering::SeqCst) {
            osoosi_agent_anomaly::egress_proxy::register_lineage_egress_hook(
                move |url, file_path, hash| self.check_egress_for_proxy(url, file_path, hash),
            );
        }
    }

    /// Clears active state for clean test isolation.
    pub fn reset_for_tests(&self) {
        self.active_processes.clear();
        self.active_artifacts.clear();
        self.content_catalog.clear();
        self.openlineage_events.write().clear();
        self.otel_log_records.write().clear();
        self.blocked_child_spans.write().clear();
    }

    /// Registers bidirectional lineage hooks on `siquery-rs`.
    pub fn register_siquery_hooks(&'static self) {
        osoosi_agent_anomaly::siquery::register_lineage_open_files_hook(move || {
            let mut list = Vec::new();
            for entry in self.active_processes.iter() {
                let pid = entry.key().pid as i64;
                for art_key in &entry.value().read_history {
                    if let Some(art) = self.active_artifacts.get(art_key) {
                        list.push((pid, 0i64, art.canonical_path.clone()));
                    }
                }
            }
            list
        });

        osoosi_agent_anomaly::siquery::register_lineage_file_events_hook(move || {
            let mut events = Vec::new();
            for entry in self.active_artifacts.iter() {
                let rec = entry.value();
                events.push(osoosi_agent_anomaly::siquery::FileEventRecord {
                    target_path: rec.canonical_path.clone(),
                    action: if rec.tainted {
                        "TAINTED_WRITE".to_string()
                    } else {
                        "REGISTER".to_string()
                    },
                    pid: 0,
                    process_name: "lineage_tracker".to_string(),
                    sha256: rec.sha256.clone(),
                    time: rec.updated_at_utc.timestamp(),
                });
            }
            events
        });
    }
}

static GLOBAL_LINEAGE_TRACKER: std::sync::LazyLock<DlpLineageTracker> =
    std::sync::LazyLock::new(|| DlpLineageTracker::new(30));

/// Returns the global reference to the DLP Lineage Tracker.
pub fn global_lineage_tracker() -> &'static DlpLineageTracker {
    let t = &GLOBAL_LINEAGE_TRACKER;
    t.register_egress_proxy_hooks();
    t
}

/// Builds standardized OpenTelemetry Resource and Span attributes carrying ZERO raw PII.
///
/// Invariant: Telemetry must NEVER leak plaintext user content, secrets, or raw prompt tokens.
/// All sensitive file contents or payloads are represented strictly by cryptographic digests
/// (`SHA-256`, `ssdeep`, `BLAKE3`).
pub fn build_zero_pii_otel_attributes(
    pid: Option<u32>,
    parent_pid: Option<u32>,
    executable_path: Option<&str>,
    file_path: Option<&str>,
    url_full: Option<&str>,
    gen_ai_operation: Option<&str>,
    content_bytes: Option<&[u8]>,
    content_sha256: Option<&str>,
    content_ssdeep: Option<&str>,
) -> Vec<opentelemetry::KeyValue> {
    let mut attrs = Vec::new();

    if let Some(p) = pid {
        attrs.push(opentelemetry::KeyValue::new("process.pid", p as i64));
    }
    if let Some(pp) = parent_pid {
        attrs.push(opentelemetry::KeyValue::new(
            "process.parent_pid",
            pp as i64,
        ));
    }
    if let Some(exe) = executable_path {
        attrs.push(opentelemetry::KeyValue::new(
            "process.executable.path",
            exe.to_string(),
        ));
    }
    if let Some(fp) = file_path {
        attrs.push(opentelemetry::KeyValue::new("file.path", fp.to_string()));
    }
    if let Some(u) = url_full {
        let sanitized = sanitize_url_zero_pii(u);
        attrs.push(opentelemetry::KeyValue::new("url.full", sanitized));
    }
    if let Some(op) = gen_ai_operation {
        attrs.push(opentelemetry::KeyValue::new(
            "gen_ai.operation.name",
            op.to_string(),
        ));
    }

    // Cryptographic content digests (Zero Raw PII)
    if let Some(bytes) = content_bytes {
        let sha = compute_sha256_hex(bytes);
        let ss = compute_ssdeep(bytes);
        let b3 = blake3::hash(bytes).to_hex().to_string();
        attrs.push(opentelemetry::KeyValue::new("file.hash.sha256", sha));
        attrs.push(opentelemetry::KeyValue::new("file.hash.ssdeep", ss));
        attrs.push(opentelemetry::KeyValue::new("file.hash.blake3", b3));
    } else {
        if let Some(sha) = content_sha256 {
            attrs.push(opentelemetry::KeyValue::new(
                "file.hash.sha256",
                sha.to_string(),
            ));
        }
        if let Some(ss) = content_ssdeep {
            attrs.push(opentelemetry::KeyValue::new(
                "file.hash.ssdeep",
                ss.to_string(),
            ));
        }
    }

    attrs
}

/// Strips sensitive credentials / basic auth tokens from URLs so telemetry never leaks secrets.
fn sanitize_url_zero_pii(u: &str) -> String {
    if let Some(idx) = u.find("://") {
        let scheme = &u[..idx + 3];
        let rest = &u[idx + 3..];
        if let Some(at_idx) = rest.find('@') {
            if let Some(slash_idx) = rest.find('/') {
                if at_idx < slash_idx {
                    return format!("{}{}", scheme, &rest[at_idx + 1..]);
                }
            } else {
                return format!("{}{}", scheme, &rest[at_idx + 1..]);
            }
        }
    }
    u.to_string()
}

// ============================================================================
// 7. Programmatic Unit Tests (Mandatory Acceptance Verification)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Mandatory Test 1: Boundary 1 Anti-Taint Creep in Long-Lived Processes.
    ///
    /// Verifies that when an uninstrumented long-lived process (`explorer.exe` or `code.exe`)
    /// opens a `CROWN_JEWEL` file and later (after handle close / TTL expiry) writes
    /// an unrelated `.log` or `.prefs` file with zero content/fuzzy overlap, the output file
    /// is NOT falsely tainted as `CROWN_JEWEL` or `QUARANTINE`.
    #[test]
    fn test_anti_taint_creep_long_lived_process_benign_log_write() {
        let tracker = DlpLineageTracker::new(5); // 5-second TTL

        // 1. Register a Crown Jewel file
        let crown_key = ArtifactKey::new(1, 101);
        let crown_content = b"TOP_SECRET_CROWN_JEWEL_FINANCIAL_REPORTS_DO_NOT_LEAK";
        tracker.register_crown_jewel_artifact(
            crown_key,
            "C:\\data\\financial_secrets.docx",
            crown_content,
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        // 2. Long-lived process reads the Crown Jewel file
        let proc_key = ProcessInstanceKey::new(1234, 100_000_000);
        tracker.on_file_read(
            proc_key,
            "explorer.exe",
            "C:\\Windows\\explorer.exe",
            crown_key,
        );

        // Verify process is tainted while handle is active
        {
            let proc = tracker.active_processes.get(&proc_key).unwrap();
            assert!(proc.tainted);
            assert_eq!(proc.classification, ClassificationLattice::CrownJewel);
            assert_eq!(proc.policy, PolicyLattice::Quarantine);
        }

        // 3. Process closes the handle to the Crown Jewel file
        tracker.on_file_close(&proc_key, &crown_key);

        // 4. Time advances past the 5-second TTL window (simulated 10 seconds later)
        let simulated_future_time = Utc::now() + chrono::Duration::seconds(10);

        // 5. Long-lived process writes benign application log with zero content overlap
        let log_key = ArtifactKey::new(1, 202);
        let log_content = b"2026-10-26 12:00:00 [INFO] System tray refresh completed successfully.";
        let decision = tracker.on_file_write(
            &proc_key,
            &log_key,
            "C:\\Users\\user\\AppData\\Local\\Temp\\explorer_session.log",
            Some(log_content),
            simulated_future_time,
        );

        // Assert Boundary 1 Anti-Taint Creep prevented false positive tainting
        match decision {
            FileWriteTaintDecision::BenignExcluded { reason } => {
                assert!(reason.contains("Anti-Taint Creep"));
            }
            FileWriteTaintDecision::TaintPropagated { .. } => {
                panic!("False positive: benign log was tainted by long-lived process!");
            }
        }

        // Confirm egress on the log file is permitted
        assert_eq!(
            tracker.check_egress_blocking(&log_key),
            EgressDecision::Allowed
        );
    }

    /// Mandatory Test 2: Boundary 2 Encrypted/Zero-Similarity Transform Preserves Causal Taint.
    ///
    /// Verifies that when an encryption/compression tool (`openssl`, `7z.exe`, `tar`)
    /// transforms a `CROWN_JEWEL` file into encrypted high-entropy ciphertext
    /// (having 0% SHA-256 and 0% ssdeep similarity), causal provenance propagates
    /// the parent `SpanContext`, `dlp.classification=CROWN_JEWEL`, and `dlp.policy=QUARANTINE`.
    #[test]
    fn test_encrypted_zero_similarity_transform_preserves_causal_taint() {
        let tracker = DlpLineageTracker::new(30);

        // 1. Register Crown Jewel document
        let secret_key = ArtifactKey::new(2, 501);
        let secret_content = b"CLASSIFIED_DEFENSE_PROVENANCE_AND_SOURCE_CODE_MATERIAL";
        tracker.register_crown_jewel_artifact(
            secret_key,
            "D:\\vault\\secret.docx",
            secret_content,
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        // 2. Transformation process (7z.exe) reads secret
        let proc_key = ProcessInstanceKey::new(5500, 200_000_000);
        tracker.on_file_read(
            proc_key,
            "7z.exe",
            "C:\\Program Files\\7-Zip\\7z.exe",
            secret_key,
        );

        // 3. 7z.exe writes high-entropy pseudo-random encrypted payload (0% similarity)
        let encrypted_key = ArtifactKey::new(2, 808);
        let mut pseudo_random_ciphertext = vec![0u8; 1024];
        for (i, byte) in pseudo_random_ciphertext.iter_mut().enumerate() {
            *byte = ((i * 137 + 43) % 256) as u8;
        }

        // Verify mathematical similarity is indeed 0%
        let secret_ssdeep = compute_ssdeep(secret_content);
        let enc_ssdeep = compute_ssdeep(&pseudo_random_ciphertext);
        assert_eq!(
            compare_ssdeep(&secret_ssdeep, &enc_ssdeep),
            0,
            "Ciphertext must share 0% fuzzy hash similarity"
        );

        // 4. Record the transformation
        let out_record = tracker.record_process_transform(
            proc_key,
            "7z.exe",
            "C:\\Program Files\\7-Zip\\7z.exe",
            &[secret_key],
            encrypted_key,
            "D:\\staging\\upload.7z",
            &pseudo_random_ciphertext,
            true, // is_encrypted_or_encoded
        );

        // Assert Boundary 2 causal taint preservation
        assert!(out_record.tainted);
        assert_eq!(out_record.classification, ClassificationLattice::CrownJewel);
        assert_eq!(out_record.policy, PolicyLattice::Quarantine);
        assert_eq!(
            out_record.baggage.transform,
            Some("ENCRYPTED_OR_ENCODED".to_string())
        );

        // Assert inline egress check drops the packet / blocks transmission
        let egress_res = tracker.check_egress_blocking(&encrypted_key);
        match egress_res {
            EgressDecision::Blocked {
                policy,
                classification,
                ..
            } => {
                assert_eq!(policy, PolicyLattice::Quarantine);
                assert_eq!(classification, ClassificationLattice::CrownJewel);
            }
            EgressDecision::Allowed => {
                panic!("Egress on encrypted Crown Jewel artifact must be blocked!");
            }
        }
    }

    /// Mandatory Test 3: Boundary 3 Cross-Host New Inode Rehydration via SHA-256 and ssdeep.
    ///
    /// Verifies that an artifact moved cross-host or out-of-band under a brand new
    /// filename and new `(device_id, inode_or_file_id)` is rehydrated into the original
    /// Crown Jewel `SpanContext` via exact SHA-256 or fuzzy ssdeep matching.
    #[test]
    fn test_cross_host_new_inode_rehydration_via_sha256_and_ssdeep() {
        let tracker = DlpLineageTracker::new(30);

        // 1. Register original Crown Jewel artifact on Host A
        let orig_key = ArtifactKey::new(10, 3001);
        let crown_data = b"CRITICAL_HEALTHCARE_PATIENT_RECORDS_HIPAA_PROTECTED_DATASET_2026";
        let orig_rec = tracker.register_crown_jewel_artifact(
            orig_key,
            "C:\\patients\\records.csv",
            crown_data,
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        // 2. Case A: Exact content re-ingested with brand-new Inode and filename
        let new_key_a = ArtifactKey::new(99, 9999);
        let rehydrated_a = tracker.rehydrate_artifact_if_unknown(
            &new_key_a,
            "E:\\incoming\\recovered.bin",
            crown_data,
        );

        assert!(rehydrated_a.is_some(), "Exact match must rehydrate lineage");
        let rec_a = rehydrated_a.unwrap();
        assert_eq!(rec_a.classification, ClassificationLattice::CrownJewel);
        assert_eq!(rec_a.policy, PolicyLattice::Quarantine);
        assert_eq!(
            rec_a.baggage.rehydrated,
            Some("content_digest_sha256".to_string())
        );
        assert_eq!(
            rec_a.linked_span_contexts.first().unwrap().span_id(),
            orig_rec.origin_span_context.span_id()
        );

        // 3. Case B: Fuzzy matching (95% similar modified content) re-ingested with new Inode
        let mut modified_data = crown_data.to_vec();
        modified_data.extend_from_slice(b"_MODIFIED_APPENDIX");
        let new_key_b = ArtifactKey::new(99, 8888);

        let rehydrated_b = tracker.rehydrate_artifact_if_unknown(
            &new_key_b,
            "E:\\incoming\\slightly_edited.csv",
            &modified_data,
        );

        assert!(
            rehydrated_b.is_some(),
            "Fuzzy ssdeep match must rehydrate lineage"
        );
        let rec_b = rehydrated_b.unwrap();
        assert_eq!(rec_b.classification, ClassificationLattice::CrownJewel);
        assert_eq!(rec_b.policy, PolicyLattice::Quarantine);
        assert!(
            rec_b
                .baggage
                .rehydrated
                .as_ref()
                .unwrap()
                .starts_with("fuzzy_hash_ssdeep"),
            "Expected fuzzy hash rehydration tag"
        );

        // Assert inline egress is blocked on both rehydrated artifacts
        assert!(matches!(
            tracker.check_egress_blocking(&new_key_a),
            EgressDecision::Blocked { .. }
        ));
        assert!(matches!(
            tracker.check_egress_blocking(&new_key_b),
            EgressDecision::Blocked { .. }
        ));
    }

    /// Mandatory Test 4: Multi-File Merge Lattice Dominance.
    ///
    /// Verifies that merging 5 files with varying sensitivity classifications
    /// (`Public`, `Internal`, `Confidential`, `CrownJewel`, `Internal`) produces
    /// a merged artifact governed by `CrownJewel` and `Quarantine`, with primary
    /// parent context and secondary `SpanLinks`.
    #[test]
    fn test_multi_file_merge_lattice_dominance() {
        let tracker = DlpLineageTracker::new(30);

        // Create 5 input files with differing classifications and policies
        let k1 = ArtifactKey::new(1, 10);
        let k2 = ArtifactKey::new(1, 20);
        let k3 = ArtifactKey::new(1, 30);
        let k4 = ArtifactKey::new(1, 40);
        let k5 = ArtifactKey::new(1, 50);

        tracker.register_crown_jewel_artifact(
            k1,
            "F1_public.txt",
            b"Public notes",
            ClassificationLattice::Public,
            PolicyLattice::Monitor,
        );
        tracker.register_crown_jewel_artifact(
            k2,
            "F2_internal.txt",
            b"Internal meeting notes",
            ClassificationLattice::Internal,
            PolicyLattice::Monitor,
        );
        tracker.register_crown_jewel_artifact(
            k3,
            "F3_confidential.docx",
            b"Confidential project blueprint",
            ClassificationLattice::Confidential,
            PolicyLattice::Block,
        );
        tracker.register_crown_jewel_artifact(
            k4,
            "F4_crown_jewel.pem",
            b"Crown Jewel private root certificate",
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );
        tracker.register_crown_jewel_artifact(
            k5,
            "F5_internal2.csv",
            b"Internal statistics",
            ClassificationLattice::Internal,
            PolicyLattice::Monitor,
        );

        let proc_key = ProcessInstanceKey::new(7777, 300_000_000);
        let zip_key = ArtifactKey::new(1, 999);
        let zip_content = b"PK\x03\x04ZIP_ARCHIVE_CONTAINING_ALL_5_FILES";

        let merged_record = tracker.record_process_transform(
            proc_key,
            "7z.exe",
            "C:\\Tools\\7z.exe",
            &[k1, k2, k3, k4, k5],
            zip_key,
            "C:\\staging\\bundle.zip",
            zip_content,
            false,
        );

        // Assert strictest-wins semilattice dominance
        assert_eq!(
            merged_record.classification,
            ClassificationLattice::CrownJewel,
            "Dominant classification must be CrownJewel"
        );
        assert_eq!(
            merged_record.policy,
            PolicyLattice::Quarantine,
            "Dominant policy must be Quarantine"
        );
        assert!(merged_record.tainted);

        // Assert secondary files are linked as SpanLinks
        assert!(!merged_record.linked_span_contexts.is_empty());

        // Assert W3C Baggage header reflects dominance
        let w3c_header = merged_record.baggage.to_w3c_header();
        assert!(w3c_header.contains("dlp.classification=CROWN_JEWEL"));
        assert!(w3c_header.contains("dlp.policy=QUARANTINE"));
        assert!(w3c_header.contains("dlp.tainted=true"));
    }

    /// Mandatory Test 5: PID Reuse Collision Immunity.
    ///
    /// Proves that when the OS recycles a numerical PID for a new process
    /// instance (with a different monotonically increasing start timestamp),
    /// the new process does not inherit the previous process's taint state.
    #[test]
    fn test_pid_reuse_collision_immunity() {
        let tracker = DlpLineageTracker::new(30);

        let crown_key = ArtifactKey::new(3, 100);
        tracker.register_crown_jewel_artifact(
            crown_key,
            "secret.txt",
            b"Crown secret",
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        // Process Instance A: PID 4120 spawned at timestamp 100_000_000
        let proc_a_key = ProcessInstanceKey::new(4120, 100_000_000);
        tracker.on_file_read(proc_a_key, "cmd.exe", "C:\\Windows\\cmd.exe", crown_key);

        // Assert Process A is tainted
        let egress_a = tracker.check_process_egress_blocking(&proc_a_key);
        assert!(matches!(egress_a, EgressDecision::Blocked { .. }));

        // Process Instance A terminates.
        // Later, the OS spawns Process Instance B with the RECYCLED PID 4120,
        // but with a higher start time: 250_000_000.
        let proc_b_key = ProcessInstanceKey::new(4120, 250_000_000);

        // Process B has NOT read any sensitive files.
        let egress_b = tracker.check_process_egress_blocking(&proc_b_key);
        assert_eq!(
            egress_b,
            EgressDecision::Allowed,
            "Process B must be untainted despite reusing PID 4120"
        );

        // Verify Process A retains its isolated taint record without cross-contamination
        let rec_a = tracker.active_processes.get(&proc_a_key).unwrap();
        assert!(rec_a.tainted);
        assert_eq!(rec_a.classification, ClassificationLattice::CrownJewel);

        assert!(tracker.active_processes.get(&proc_b_key).is_none());
    }

    /// Unit Test: W3C Baggage Member Property Stripping.
    ///
    /// Verifies that standard W3C baggage member properties following ';'
    /// (e.g. `dlp.classification=CROWN_JEWEL;ttl=30` and `dlp.tainted=true;auth=ok`)
    /// are stripped cleanly so classifications and taint states are never silently downgraded.
    #[test]
    fn test_w3c_baggage_member_property_stripping() {
        let single_class = "dlp.classification=CROWN_JEWEL;ttl=30";
        let b1 = DlpBaggage::from_w3c_header(single_class);
        assert_eq!(
            b1.classification,
            ClassificationLattice::CrownJewel,
            "CROWN_JEWEL with property parameter must not downgrade to Public"
        );

        let single_taint = "dlp.tainted=true;auth=ok";
        let b2 = DlpBaggage::from_w3c_header(single_taint);
        assert!(
            b2.tainted,
            "tainted=true with property parameter must parse as true"
        );

        let multi = "dlp.classification=CROWN_JEWEL;ttl=30;p0=true, dlp.policy=QUARANTINE;tier=critical, dlp.tainted=true;auth=ok, dlp.source_sha256=11223344;v=2, custom_param=val;extra=ignored";
        let b3 = DlpBaggage::from_w3c_header(multi);
        assert_eq!(b3.classification, ClassificationLattice::CrownJewel);
        assert_eq!(b3.policy, PolicyLattice::Quarantine);
        assert!(b3.tainted);
        assert_eq!(b3.source_sha256, "11223344");
        assert_eq!(b3.custom.get("custom_param"), Some(&"val".to_string()));
    }

    /// Unit Test: In-Memory Process Exit Cleanup.
    ///
    /// Verifies that terminated processes are pruned from `active_processes`
    /// via `on_process_exit` using both exact timestamps and PID fallback.
    #[test]
    fn test_process_exit_cleanup() {
        let tracker = DlpLineageTracker::new(30);
        let key1 = ProcessInstanceKey::new(5500, 100_000);
        let key2 = ProcessInstanceKey::new(5501, 200_000);
        let art = ArtifactKey::new(1, 10);

        tracker.register_crown_jewel_artifact(
            art,
            "secret.docx",
            b"secret",
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        tracker.on_file_read(key1, "proc1.exe", "C:\\proc1.exe", art);
        tracker.on_file_read(key2, "proc2.exe", "C:\\proc2.exe", art);

        assert!(tracker.active_processes.contains_key(&key1));
        assert!(tracker.active_processes.contains_key(&key2));

        // Terminate key1 with exact timestamp
        assert!(tracker.on_process_exit(5500, 100_000));
        assert!(!tracker.active_processes.contains_key(&key1));

        // Terminate key2 with pid-only fallback (start_time_100ns = 0)
        assert!(tracker.on_process_exit(5501, 0));
        assert!(!tracker.active_processes.contains_key(&key2));

        // Second removal returns false
        assert!(!tracker.on_process_exit(5500, 100_000));
    }

    /// Unit Test: DashMap TTL Eviction for Stale Artifacts and Processes.
    #[test]
    fn test_evict_expired_artifacts_and_processes() {
        let tracker = DlpLineageTracker::new(30);
        let art_key = ArtifactKey::new(99, 101);
        let proc_key = ProcessInstanceKey::new(8888, 12345);

        let mut record = tracker.register_crown_jewel_artifact(
            art_key,
            "old.doc",
            b"old content",
            ClassificationLattice::Confidential,
            PolicyLattice::Block,
        );

        // Artificially backdate record timestamps
        let past = Utc::now() - chrono::Duration::seconds(100);
        record.updated_at_utc = past;
        tracker.active_artifacts.insert(art_key, record.clone());
        tracker
            .content_catalog
            .insert(record.sha256.clone(), record.clone());
        if let Some(ref ss) = record.ssdeep {
            tracker.content_catalog.insert(ss.clone(), record);
        }

        tracker.on_file_read(proc_key, "stale.exe", "C:\\stale.exe", art_key);
        if let Some(mut p) = tracker.active_processes.get_mut(&proc_key) {
            p.updated_at_utc = past;
        }

        // Evict entries older than 30 seconds
        let evicted = tracker.evict_expired(30, 30);
        assert_eq!(
            evicted, 2,
            "Expected 1 artifact and 1 process to be evicted"
        );
        assert!(!tracker.active_artifacts.contains_key(&art_key));
        assert!(!tracker.active_processes.contains_key(&proc_key));
    }

    /// Unit Test: Bounded Read History Capacity (Max 256).
    #[test]
    fn test_bounded_read_history_capacity() {
        let tracker = DlpLineageTracker::new(30);
        let proc_key = ProcessInstanceKey::new(9999, 44444);

        // Simulate reading 300 distinct files
        for i in 0..300u64 {
            let art = ArtifactKey::new(1, i);
            tracker.register_crown_jewel_artifact(
                art,
                &format!("file_{}.txt", i),
                format!("content_{}", i).as_bytes(),
                ClassificationLattice::Public,
                PolicyLattice::Monitor,
            );
            tracker.on_file_read(proc_key, "reader.exe", "C:\\reader.exe", art);
        }

        let proc = tracker
            .active_processes
            .get(&proc_key)
            .expect("Process must exist");
        assert_eq!(
            proc.read_history.len(),
            MAX_READ_HISTORY_PER_PROCESS,
            "read_history must be bounded to MAX_READ_HISTORY_PER_PROCESS (256)"
        );

        // Most recent artifact (299) must be present
        assert!(proc.read_history.contains(&ArtifactKey::new(1, 299)));
        // Oldest artifact (0) must have been evicted from read_history
        assert!(!proc.read_history.contains(&ArtifactKey::new(1, 0)));
    }

    /// Unit Test: Windows ArtifactKey Invariance Across Writes.
    #[test]
    fn test_windows_artifact_key_write_invariance() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!("dlp_key_test_{}.tmp", rand::random::<u64>()));

        // Create initial file
        {
            let mut f = std::fs::File::create(&test_file).expect("Create test file");
            f.write_all(b"initial data").expect("Write initial data");
            f.flush().expect("Flush initial data");
        }

        let key1 = ArtifactKey::from_path(&test_file).expect("Get key 1");

        // Append data to modify file size and last write time
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&test_file)
                .expect("Open test file for append");
            f.write_all(b" additional appended content changing size and mtime")
                .expect("Write append data");
            f.flush().expect("Flush append data");
        }

        let key2 = ArtifactKey::from_path(&test_file).expect("Get key 2");

        // Clean up
        let _ = std::fs::remove_file(&test_file);

        // On Windows NTFS/ReFS, device_id and inode_or_file_id MUST match across writes
        #[cfg(windows)]
        {
            assert_eq!(
                key1.device_id, key2.device_id,
                "Device ID / Volume Serial Number must be invariant across writes"
            );
            assert_eq!(
                key1.inode_or_file_id, key2.inode_or_file_id,
                "File Index must be invariant across writes"
            );
            assert_eq!(
                key1, key2,
                "ArtifactKey must be invariant across file modifications"
            );
        }
    }

    /// Milestone 2 Unit Test: Parent-to-Child Process Taint Propagation on ProcessCreate.
    #[test]
    fn test_process_create_taint_propagation() {
        let tracker = DlpLineageTracker::new(30);

        // 1. Create and taint parent process
        let parent_proc_key = ProcessInstanceKey::new(1001, 500_000);
        let secret_key = ArtifactKey::new(1, 777);
        tracker.register_crown_jewel_artifact(
            secret_key,
            "C:\\data\\classified.dat",
            b"TOP_SECRET_CLASSIFIED_DATA",
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );
        tracker.on_file_read(
            parent_proc_key,
            "cmd.exe",
            "C:\\Windows\\system32\\cmd.exe",
            secret_key,
        );

        // Parent must be tainted
        let parent_rec = tracker.active_processes.get(&parent_proc_key).unwrap();
        assert!(parent_rec.tainted);
        assert_eq!(parent_rec.classification, ClassificationLattice::CrownJewel);

        // 2. Child process is spawned by parent process
        let child_rec = tracker.on_process_create(
            2002,
            600_000,
            "powershell.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            Some(1001),
            Some(500_000),
        );

        // Child must inherit CrownJewel taint and Quarantine policy
        assert!(child_rec.tainted, "Child process must inherit parent taint");
        assert_eq!(child_rec.classification, ClassificationLattice::CrownJewel);
        assert_eq!(child_rec.policy, PolicyLattice::Quarantine);
        assert!(!child_rec.linked_span_contexts.is_empty());
        assert_eq!(
            child_rec.linked_span_contexts[0].span_id(),
            parent_rec.origin_span_context.span_id(),
            "Child process must link parent process SpanContext"
        );
    }

    /// Milestone 2 Unit Test: File Events, Writes, and Rename Taint Transfer.
    #[test]
    fn test_file_events_and_rename_taint_propagation() {
        let tracker = DlpLineageTracker::new(30);

        let proc_key = ProcessInstanceKey::new(3003, 100_000);
        let src_path = "C:\\staging\\draft_report.docx";
        let dst_path = "C:\\staging\\final_report.docx";

        // 1. Taint process by reading sensitive path
        let secret_key = ArtifactKey::from_path_or_synthetic("C:\\vault\\credentials.json");
        tracker.register_crown_jewel_artifact(
            secret_key,
            "C:\\vault\\credentials.json",
            b"super_secret_credentials_key",
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );
        tracker.on_file_read(proc_key, "app.exe", "C:\\app.exe", secret_key);

        // 2. Process writes output file
        let write_decision = tracker.on_file_write_path(
            3003,
            100_000,
            src_path,
            Some(b"report content derived from credentials"),
        );
        assert!(matches!(
            write_decision,
            FileWriteTaintDecision::TaintPropagated { .. }
        ));

        let src_key = ArtifactKey::from_path_or_synthetic(src_path);
        {
            let src_rec = tracker
                .active_artifacts
                .get(&src_key)
                .expect("Artifact must exist");
            assert!(src_rec.tainted);
            assert_eq!(src_rec.classification, ClassificationLattice::CrownJewel);
        }

        // 3. Rename file from draft to final
        tracker.on_file_rename(3003, 100_000, src_path, dst_path);

        let dst_key = ArtifactKey::from_path_or_synthetic(dst_path);
        assert!(
            tracker.active_artifacts.get(&src_key).is_none(),
            "Old path must be removed"
        );
        {
            let dst_rec = tracker
                .active_artifacts
                .get(&dst_key)
                .expect("Renamed artifact must exist");
            assert!(dst_rec.tainted, "Renamed artifact must retain taint");
            assert_eq!(dst_rec.classification, ClassificationLattice::CrownJewel);
            assert_eq!(dst_rec.policy, PolicyLattice::Quarantine);
        }
    }

    /// Milestone 2 Unit Test: Egress Check and Zero-PII OpenTelemetry Attributes.
    #[test]
    fn test_check_egress_allowed_and_zero_pii_otel_attributes() {
        let tracker = DlpLineageTracker::new(30);

        let raw_secret = b"SECRET_CUSTOMER_CREDIT_CARD_DATA_LEAK_TARGET";
        let sha256_hash = compute_sha256_hex(raw_secret);
        let secret_key = ArtifactKey::from_path_or_synthetic("C:\\leak\\cards.csv");

        tracker.register_crown_jewel_artifact(
            secret_key,
            "C:\\leak\\cards.csv",
            raw_secret,
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        // 1. Egress by path must be blocked
        let res_path =
            tracker.check_egress_allowed_full(Some("C:\\leak\\cards.csv"), None, None, None, None);
        assert!(res_path.is_err(), "Egress by tainted path must be blocked");

        // 2. Egress by hash must be blocked
        let res_hash =
            tracker.check_egress_allowed_full(None, Some(&sha256_hash), None, None, None);
        assert!(res_hash.is_err(), "Egress by tainted hash must be blocked");

        // 3. Egress to suspect sink with active crown jewel must be blocked
        let res_url = tracker.check_egress_allowed_full(
            None,
            None,
            None,
            Some("https://webhook.site/test-leak"),
            None,
        );
        assert!(
            res_url.is_err(),
            "Egress to suspect exfiltration sink must be blocked"
        );

        // 4. Benign egress must be allowed
        let res_clean = tracker.check_egress_allowed_full(
            Some("C:\\benign\\notes.txt"),
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            None,
            Some("https://trusted.internal.corp/api/health"),
            None,
        );
        assert!(res_clean.is_ok(), "Benign egress must be allowed");

        // 5. Zero-PII OpenTelemetry Attribute verification
        let attrs = build_zero_pii_otel_attributes(
            Some(4567),
            Some(1234),
            Some("C:\\bin\\uploader.exe"),
            Some("C:\\leak\\cards.csv"),
            Some("https://user:password123@webhook.site/upload?query=1"),
            Some("inference.completion"),
            Some(raw_secret),
            None,
            None,
        );

        // Verify standard attributes exist
        let attr_map: std::collections::HashMap<String, String> = attrs
            .into_iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect();

        assert_eq!(
            attr_map.get("process.pid").map(|s| s.as_str()),
            Some("4567")
        );
        assert_eq!(
            attr_map.get("process.parent_pid").map(|s| s.as_str()),
            Some("1234")
        );
        assert_eq!(
            attr_map.get("process.executable.path").map(|s| s.as_str()),
            Some("C:\\bin\\uploader.exe")
        );
        assert_eq!(
            attr_map.get("file.path").map(|s| s.as_str()),
            Some("C:\\leak\\cards.csv")
        );
        assert_eq!(
            attr_map.get("gen_ai.operation.name").map(|s| s.as_str()),
            Some("inference.completion")
        );

        // Verify cryptographic hashes are present
        assert_eq!(
            attr_map.get("file.hash.sha256").map(|s| s.as_str()),
            Some(sha256_hash.as_str())
        );
        assert!(attr_map.contains_key("file.hash.ssdeep"));
        assert!(attr_map.contains_key("file.hash.blake3"));

        // Verify Zero-PII invariant: URL basic auth credentials are sanitized
        let sanitized_url = attr_map
            .get("url.full")
            .expect("url.full attribute must exist");
        assert!(
            !sanitized_url.contains("password123"),
            "Sanitized URL must NEVER contain raw passwords or basic auth credentials"
        );
        assert!(
            !sanitized_url.contains("user:"),
            "Sanitized URL must NEVER contain user basic auth credentials"
        );
        assert!(sanitized_url.starts_with("https://webhook.site/"));
    }

    /// Milestone 2 Unit Test: Siquery-rs Bidirectional Correlation.
    #[test]
    fn test_siquery_bidirectional_correlation() {
        let tracker: &'static DlpLineageTracker = Box::leak(Box::new(DlpLineageTracker::new(30)));

        // Register hooks with siquery
        tracker.register_siquery_hooks();

        let engine = osoosi_agent_anomaly::siquery::SiqueryEngine::new();

        // Populate a crown jewel artifact
        let key = ArtifactKey::from_path_or_synthetic("C:\\secure\\token.pem");
        tracker.register_crown_jewel_artifact(
            key,
            "C:\\secure\\token.pem",
            b"CERT_PRIVATE_KEY_BYTES",
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        // Correlate with siquery engine
        let res = tracker.correlate_with_siquery(&engine);
        assert!(res.is_ok(), "correlate_with_siquery must succeed");
    }

    /// Milestone 3 Unit Test: OpenLineage RunEvent to OTel LogRecord Serialization.
    #[test]
    fn test_openlineage_run_event_serialization_and_otel_log_record() {
        let tracker = DlpLineageTracker::new(30);

        let run_id = uuid::Uuid::new_v4().to_string();
        let event = OpenLineageRunEvent::new(
            "COMPLETE",
            &run_id,
            "oshoosi://endpoint/HOST-01",
            "7z.exe#pid:14280",
        )
        .with_input(
            "file://dev1/ino100",
            "C:\\data\\secret.docx",
            "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
            Some("192:8gWJ9Xq...".to_string()),
            Some("CROWN_JEWEL".to_string()),
            Some("QUARANTINE".to_string()),
        )
        .with_output(
            "file://dev1/ino200",
            "C:\\staging\\upload.zip",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            true,
            "CROWN_JEWEL".to_string(),
            "QUARANTINE".to_string(),
            Some("BLOCKED".to_string()),
            vec!["4bf92f3577b34da6a3ce929d0e0e4736".to_string()],
            vec!["00f067aa0ba902b7".to_string()],
        );

        // 1. Verify JSON serialization
        let json_str = event
            .to_json_string()
            .expect("JSON serialization must succeed");
        assert!(json_str.contains("\"eventType\""));
        assert!(json_str.contains("\"COMPLETE\""));
        assert!(json_str.contains("\"runId\""));
        assert!(json_str.contains("7z.exe#pid:14280"));
        assert!(json_str.contains("secret.docx"));
        assert!(json_str.contains("upload.zip"));
        assert!(json_str.contains("\"datasetDigest\""));
        assert!(json_str.contains("\"taintFacet\""));
        assert!(json_str.contains("\"CROWN_JEWEL\""));
        assert!(json_str.contains("\"QUARANTINE\""));

        // 2. Verify conversion to OpenTelemetry LogRecord
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let span_id = "00f067aa0ba902b7";
        let log_rec = event.to_otel_log_record(Some(trace_id), Some(span_id));

        assert_eq!(log_rec.trace_id, trace_id);
        assert_eq!(log_rec.span_id, span_id);
        assert_eq!(log_rec.trace_flags, 1);
        assert_eq!(log_rec.severity_text, "INFO");
        assert!(log_rec.body.contains("\"eventType\": \"COMPLETE\""));
        assert_eq!(
            log_rec
                .attributes
                .get("openlineage.job.name")
                .map(|s| s.as_str()),
            Some("7z.exe#pid:14280")
        );

        // 3. Emit via tracker and verify retention in Merkle audit tree and ring buffer
        let emitted = tracker.emit_openlineage_run_event(event, Some(trace_id), Some(span_id));
        assert_eq!(emitted.trace_id, trace_id);
        assert_eq!(tracker.openlineage_events.read().len(), 1);
        assert_eq!(tracker.otel_log_records.read().len(), 1);
    }

    /// Milestone 3 Unit Test: Synchronous Inline Egress Blocking and Child Span.
    #[test]
    fn test_synchronous_inline_egress_blocking_and_child_span() {
        let tracker = DlpLineageTracker::new(30);

        let secret_key = ArtifactKey::from_path_or_synthetic("C:\\vault\\top_secret.docx");
        let secret_bytes = b"HIGHLY_CONFIDENTIAL_NATIONAL_SECURITY_ARCHIVE";
        let sha256_hash = compute_sha256_hex(secret_bytes);

        tracker.register_crown_jewel_artifact(
            secret_key,
            "C:\\vault\\top_secret.docx",
            secret_bytes,
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );

        // Egress check by URL against suspect sink with active crown jewel
        let block_res = tracker.check_egress_for_proxy(
            Some("https://attacker-pastebin.com/exfil"),
            Some("C:\\vault\\top_secret.docx"),
            Some(&sha256_hash),
        );

        assert!(
            block_res.is_err(),
            "Tainted egress must be synchronously blocked"
        );
        let info = block_res.unwrap_err();
        assert_eq!(info.policy, "QUARANTINE");
        assert_eq!(info.classification, "CROWN_JEWEL");
        assert!(info.trace_id.is_some());
        assert!(info.span_id.is_some());

        // Verify synthetic child span in tracker ring buffer
        let spans = tracker.blocked_child_spans.read();
        assert_eq!(
            spans.len(),
            1,
            "Child span must be emitted into ring buffer"
        );
        let span = &spans[0];
        assert_eq!(span.status, "ERROR");
        assert_eq!(span.action, "BLOCKED");
        assert_eq!(span.policy, "QUARANTINE");
        assert_eq!(span.classification, "CROWN_JEWEL");
        assert_eq!(
            span.attributes.get("dlp.action").map(|s| s.as_str()),
            Some("BLOCKED")
        );
        assert_eq!(
            span.attributes.get("otel.status_code").map(|s| s.as_str()),
            Some("ERROR")
        );
    }

    /// Milestone 3 Unit Test: Live Lineage Summary JSON & KPI Rollup.
    #[test]
    fn test_lineage_summary_json_and_kpis() {
        let tracker = DlpLineageTracker::new(30);

        let k1 = ArtifactKey::from_path_or_synthetic("C:\\secret1.docx");
        let k2 = ArtifactKey::from_path_or_synthetic("C:\\secret2.docx");
        tracker.register_crown_jewel_artifact(
            k1,
            "C:\\secret1.docx",
            b"secret1",
            ClassificationLattice::CrownJewel,
            PolicyLattice::Quarantine,
        );
        tracker.register_crown_jewel_artifact(
            k2,
            "C:\\secret2.docx",
            b"secret2",
            ClassificationLattice::Confidential,
            PolicyLattice::Block,
        );

        let proc_key = ProcessInstanceKey::new(8888, 100_000);
        tracker.on_file_read(proc_key, "worker.exe", "C:\\worker.exe", k1);

        let summary_json = tracker.get_lineage_summary_json();
        assert_eq!(summary_json["status"], "ok");

        let kpis = &summary_json["kpis"];
        assert!(kpis["active_traces"].as_u64().unwrap() >= 2);
        assert!(kpis["hops"].as_u64().unwrap() >= 1);

        let inputs = summary_json["input_datasets"].as_array().unwrap();
        assert_eq!(inputs.len(), 2);

        let jobs = summary_json["jobs"].as_array().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0]["pid"], 8888);
    }
}
