//! Google Cybernetic Agent Governance Engine (CAGE) Layer 3 `actuator_04` Substrate Routes.
//!
//! Migrated from `killswitch` PR #30 (`a0a2e36`):
//! - RFC 8785 JSON Canonicalization Scheme (JCS) with 128-bit integer float formatting (`2^63` safe)
//! - Crash-safe Ed25519-sealed `QuarantineJournal` with monotonic SHA-256 hash chaining
//! - Out-of-band RFC 8037 Ed25519 JWKS trust anchor (`CageKeyManifestResolver`)
//! - Single-use TTL-bounded `NonceReplayCache`
//! - 24-hour sliding-window CBF accumulators (`Cumulative24hTracker`, `KeyedCumulative24hTracker`)
//! - 6 CAGE Layer 3 `actuator_04` Substrate Endpoints (+ `/api/v1/cage/*` aliases):
//!   1. `GET /.well-known/jwks.json`
//!   2. `GET /v1/cage/normative-baseline/:region`
//!   3. `GET /v1/cage/attest`
//!   4. `POST /v1/cage/conformal/validate`
//!   5. `POST /v1/cage/quarantine`
//!   6. `POST /v1/cage/release`

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use osoosi_core::parking_lot::{Mutex, RwLock};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

use crate::DashboardState;

// =============================================================================
// 1. RFC 8785 JSON Canonicalization Scheme (JCS) with 128-bit Float Safety
// =============================================================================

/// Canonicalizes a JSON `Value` per RFC 8785 (ECMAScript number & UTF-16 key ordering),
/// returning canonical UTF-8 bytes.
pub fn canonicalize_substrate_jcs(val: &Value) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    serialize_jcs_val(val, &mut buf)?;
    Ok(buf)
}

/// Canonicalizes a JSON `Value` per RFC 8785, returning a UTF-8 string.
pub fn canonicalize_substrate_jcs_string(val: &Value) -> Result<String, String> {
    let bytes = canonicalize_substrate_jcs(val)?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 encoding error: {e}"))
}

fn serialize_jcs_val(val: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    match val {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(true) => buf.extend_from_slice(b"true"),
        Value::Bool(false) => buf.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                buf.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                buf.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(
                        "Non-finite number (NaN or Infinity) is not supported in RFC 8785 JCS"
                            .to_string(),
                    );
                }
                let formatted = format_ecma_float(f);
                buf.extend_from_slice(formatted.as_bytes());
            }
        }
        Value::String(s) => {
            buf.push(b'"');
            for c in s.chars() {
                match c {
                    '"' => buf.extend_from_slice(b"\\\""),
                    '\\' => buf.extend_from_slice(b"\\\\"),
                    '\x08' => buf.extend_from_slice(b"\\b"),
                    '\x0C' => buf.extend_from_slice(b"\\f"),
                    '\n' => buf.extend_from_slice(b"\\n"),
                    '\r' => buf.extend_from_slice(b"\\r"),
                    '\t' => buf.extend_from_slice(b"\\t"),
                    ch if (ch as u32) < 0x20 => {
                        let esc = format!("\\u{:04x}", ch as u32);
                        buf.extend_from_slice(esc.as_bytes());
                    }
                    ch => {
                        let mut b = [0u8; 4];
                        buf.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                    }
                }
            }
            buf.push(b'"');
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                serialize_jcs_val(elem, buf)?;
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            buf.push(b'{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // RFC 8785 §3.2.3: Keys ordered lexicographically by UTF-16 code units
            entries.sort_by(|(k1, _), (k2, _)| k1.encode_utf16().cmp(k2.encode_utf16()));
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                serialize_jcs_val(&Value::String(key.clone()), buf)?;
                buf.push(b':');
                serialize_jcs_val(value, buf)?;
            }
            buf.push(b'}');
        }
    }
    Ok(())
}

fn format_ecma_float(f: f64) -> String {
    if f == 0.0 {
        return "0".to_string();
    }
    let abs_f = f.abs();
    if abs_f >= 1e21 {
        let s = format!("{f:e}");
        if let Some(pos) = s.find('e') {
            let (mantissa, exp) = s.split_at(pos);
            let exp_val: i32 = exp[1..].parse().unwrap_or(0);
            if exp_val >= 0 {
                format!("{mantissa}e+{exp_val}")
            } else {
                format!("{mantissa}e{exp_val}")
            }
        } else {
            s
        }
    } else if abs_f < 1e-6 {
        format!("{f:e}")
    } else if f.fract() == 0.0 {
        // Use i128 so integer-valued floats >= 2^63 (e.g. 9223372036854775808.0) never saturate i64::MAX
        (f as i128).to_string()
    } else {
        f.to_string()
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// =============================================================================
// 2. Crash-Safe Ed25519-Sealed QuarantineJournal
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineLease {
    pub workload_id: String,
    pub target_pid: Option<u32>,
    pub trigger_reason: String,
    pub rule_id: String,
    pub quarantined_at: String,
    pub expires_at_unix_ms: Option<u64>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    pub seq: u64,
    pub timestamp_utc: String,
    pub action: String,
    pub workload_id: String,
    pub epoch: u64,
    pub prev_hash: String,
    pub record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JournalData {
    pub seq: u64,
    pub active_leases: BTreeMap<String, QuarantineLease>,
    pub generation_epochs: BTreeMap<String, u64>,
    pub records: Vec<JournalRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedJournalEnvelope {
    pub version: u32,
    pub kid: String,
    pub payload: JournalData,
    pub signature: String,
}

pub struct QuarantineJournal {
    journal_path: PathBuf,
    signing_key: Arc<SigningKey>,
    kid: String,
    data: Mutex<JournalData>,
    tampered_on_boot: bool,
}

impl QuarantineJournal {
    pub fn new(state_dir: PathBuf, signing_key: Arc<SigningKey>, kid: String) -> Self {
        let _ = std::fs::create_dir_all(&state_dir);
        let journal_path = state_dir.join("quarantine_journal.json");
        let mut tampered_on_boot = false;
        let mut initial_data = JournalData::default();

        if journal_path.exists() {
            match Self::load_and_verify_from_disk(&journal_path, signing_key.verifying_key()) {
                Ok(verified) => {
                    initial_data = verified;
                }
                Err(e) => {
                    error!(
                        "🚨 [CAGE-JOURNAL] Journal integrity verification failed on startup ({}): {}",
                        journal_path.display(),
                        e
                    );
                    tampered_on_boot = true;
                }
            }
        }

        Self {
            journal_path,
            signing_key,
            kid,
            data: Mutex::new(initial_data),
            tampered_on_boot,
        }
    }

    fn load_and_verify_from_disk(
        path: &std::path::Path,
        verifying_key: VerifyingKey,
    ) -> Result<JournalData, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read journal file: {e}"))?;
        let envelope: SealedJournalEnvelope = serde_json::from_str(&raw)
            .map_err(|e| format!("Malformed journal envelope JSON: {e}"))?;

        let payload_val = serde_json::to_value(&envelope.payload)
            .map_err(|e| format!("Failed to serialize payload value: {e}"))?;
        let canonical = canonicalize_substrate_jcs(&payload_val)?;
        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical);

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(envelope.signature.trim())
            .map_err(|e| format!("Invalid journal signature base64url: {e}"))?;
        if sig_bytes.len() != 64 {
            return Err("Journal signature must be 64 bytes".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(&preimage, &sig)
            .map_err(|e| format!("Ed25519 journal seal verification failed: {e}"))?;

        Self::verify_records_chain(&envelope.payload.records)?;
        Ok(envelope.payload)
    }

    fn verify_records_chain(records: &[JournalRecord]) -> Result<bool, String> {
        let mut expected_prev = "0".repeat(64);
        for (expected_seq, rec) in (1u64..).zip(records.iter()) {
            if rec.seq != expected_seq {
                return Err(format!(
                    "Non-monotonic journal sequence: expected {}, got {}",
                    expected_seq, rec.seq
                ));
            }
            if rec.prev_hash != expected_prev {
                return Err(format!(
                    "Broken journal hash chain at seq {}: expected prev {}, got {}",
                    rec.seq, expected_prev, rec.prev_hash
                ));
            }
            let computed = Self::compute_record_hash(
                rec.seq,
                &rec.timestamp_utc,
                &rec.action,
                &rec.workload_id,
                rec.epoch,
                &rec.prev_hash,
            );
            if rec.record_hash != computed {
                return Err(format!(
                    "Tampered journal record hash at seq {}: expected {}, got {}",
                    rec.seq, computed, rec.record_hash
                ));
            }
            expected_prev = rec.record_hash.clone();
        }
        Ok(true)
    }

    fn compute_record_hash(
        seq: u64,
        timestamp_utc: &str,
        action: &str,
        workload_id: &str,
        epoch: u64,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"CAGE_JOURNAL_RECORD_V1:");
        hasher.update(seq.to_le_bytes());
        hasher.update(b":");
        hasher.update(timestamp_utc.as_bytes());
        hasher.update(b":");
        hasher.update(action.as_bytes());
        hasher.update(b":");
        hasher.update(workload_id.as_bytes());
        hasher.update(b":");
        hasher.update(epoch.to_le_bytes());
        hasher.update(b":");
        hasher.update(prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn persist_locked(&self, data: &JournalData) -> Result<(), String> {
        let payload_val =
            serde_json::to_value(data).map_err(|e| format!("Journal value error: {e}"))?;
        let canonical = canonicalize_substrate_jcs(&payload_val)?;
        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical);

        let sig = self.signing_key.sign(&preimage);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        let envelope = SealedJournalEnvelope {
            version: 1,
            kid: self.kid.clone(),
            payload: data.clone(),
            signature: sig_b64,
        };
        let serialized = serde_json::to_vec_pretty(&envelope)
            .map_err(|e| format!("Journal serialize error: {e}"))?;

        if let Some(parent) = self.journal_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp_path = self.journal_path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            unix_now_ms()
        ));
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)
                .map_err(|e| format!("Journal temp create failed: {e}"))?;
            file.write_all(&serialized)
                .map_err(|e| format!("Journal temp write failed: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Journal temp fsync failed: {e}"))?;
        }
        std::fs::rename(&tmp_path, &self.journal_path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            format!("Atomic journal rename failed: {e}")
        })?;
        Ok(())
    }

    fn append_record_locked(data: &mut JournalData, action: &str, workload_id: &str, epoch: u64) {
        let next_seq = data.seq.saturating_add(1);
        let prev_hash = data
            .records
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let now_utc = Utc::now().to_rfc3339();
        let record_hash =
            Self::compute_record_hash(next_seq, &now_utc, action, workload_id, epoch, &prev_hash);
        data.seq = next_seq;
        data.records.push(JournalRecord {
            seq: next_seq,
            timestamp_utc: now_utc,
            action: action.to_string(),
            workload_id: workload_id.to_string(),
            epoch,
            prev_hash,
            record_hash,
        });
    }

    pub fn is_tampered(&self) -> bool {
        self.tampered_on_boot
    }

    pub fn current_seq(&self) -> u64 {
        self.data.lock().seq
    }

    pub fn get_generation_epoch(&self, workload_id: &str) -> u64 {
        *self
            .data
            .lock()
            .generation_epochs
            .get(workload_id)
            .unwrap_or(&1)
    }

    /// Monotonically advances generation epoch `Gen N -> Gen N + 1` and seals the journal.
    pub fn advance_generation_epoch(&self, workload_id: &str) -> Result<(u64, u64), String> {
        let mut guard = self.data.lock();
        let before = *guard.generation_epochs.get(workload_id).unwrap_or(&1);
        let after = before.saturating_add(1);
        guard
            .generation_epochs
            .insert(workload_id.to_string(), after);
        Self::append_record_locked(&mut guard, "ADVANCE_EPOCH", workload_id, after);
        self.persist_locked(&guard)?;
        Ok((before, after))
    }

    pub fn record_quarantine(&self, lease: QuarantineLease) -> Result<(), String> {
        let mut guard = self.data.lock();
        let epoch = *guard
            .generation_epochs
            .entry(lease.workload_id.clone())
            .or_insert(1);
        let wid = lease.workload_id.clone();
        guard.active_leases.insert(wid.clone(), lease);
        Self::append_record_locked(&mut guard, "QUARANTINE", &wid, epoch);
        self.persist_locked(&guard)
    }

    pub fn release_quarantine(&self, workload_id: &str) -> Result<Option<QuarantineLease>, String> {
        let mut guard = self.data.lock();
        let removed = guard.active_leases.remove(workload_id);
        let epoch = *guard.generation_epochs.get(workload_id).unwrap_or(&1);
        Self::append_record_locked(&mut guard, "RELEASE", workload_id, epoch);
        self.persist_locked(&guard)?;
        Ok(removed)
    }

    pub fn unexpired_leases(&self) -> Vec<QuarantineLease> {
        let now_ms = unix_now_ms();
        self.data
            .lock()
            .active_leases
            .values()
            .filter(|l| l.expires_at_unix_ms.is_none_or(|exp| exp > now_ms))
            .cloned()
            .collect()
    }

    pub fn verify_hash_chain(&self) -> Result<bool, String> {
        let guard = self.data.lock();
        Self::verify_records_chain(&guard.records)
    }

    /// Fail-closed crash/reboot recovery: if tampered on boot or any unexpired lease remains,
    /// immediately re-engages host OS kernel containment and suspends leased PIDs.
    pub async fn recover_and_re_enforce(&self) -> Result<usize, String> {
        if self.tampered_on_boot {
            let _ = osoosi_core::killchain::engage_killchain_isolation(
                "CAGE-Substrate-Journal-Recovery",
                "Fail-closed emergency quarantine: QuarantineJournal signature/chain tampering detected",
                true,
                false,
                true,
            )
            .await;
            return Err(
                "QuarantineJournal failed cryptographic verification on startup; host locked fail-closed"
                    .to_string(),
            );
        }

        let leases = self.unexpired_leases();
        if leases.is_empty() {
            return Ok(0);
        }

        let _ = osoosi_core::killchain::engage_killchain_isolation(
            "CAGE-Substrate-Journal-Recovery",
            &format!(
                "Re-enforcing {} unexpired CAGE quarantine lease(s) on startup",
                leases.len()
            ),
            true,
            false,
            true,
        )
        .await;

        if !osoosi_core::wfp::is_cargo_test_simulation_mode() {
            for lease in &leases {
                if let Some(pid) = lease.target_pid {
                    if pid > 0 {
                        let _ = osoosi_core::killchain::suspend_process_by_pid(pid);
                    }
                }
            }
        }
        Ok(leases.len())
    }
}

// =============================================================================
// 3. Out-of-Band JWKS Trust Anchor, Nonce Replay Cache, & 24h CBF Trackers
// =============================================================================

pub struct CageKeyManifestResolver {
    keys: RwLock<HashMap<String, VerifyingKey>>,
}

impl Default for CageKeyManifestResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CageKeyManifestResolver {
    pub fn new() -> Self {
        let resolver = Self {
            keys: RwLock::new(HashMap::new()),
        };
        resolver.reload_from_env();
        resolver
    }

    pub fn reload_from_env(&self) {
        if let Ok(path) = std::env::var("CAGE_TRUSTED_JWKS_PATH") {
            if !path.trim().is_empty() {
                if let Ok(raw) = std::fs::read_to_string(path.trim()) {
                    let _ = self.ingest_jwks_json(&raw);
                }
            }
        }
        if let Ok(inline_json) = std::env::var("CAGE_TRUSTED_JWKS_JSON") {
            if !inline_json.trim().is_empty() {
                let _ = self.ingest_jwks_json(&inline_json);
            }
        }
    }

    pub fn ingest_jwks_json(&self, raw_json: &str) -> Result<usize, String> {
        let parsed: Value =
            serde_json::from_str(raw_json).map_err(|e| format!("Invalid JWKS JSON: {e}"))?;
        let keys_arr = parsed
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "JWKS JSON missing 'keys' array".to_string())?;

        let mut count = 0usize;
        let mut guard = self.keys.write();
        for entry in keys_arr {
            let kty = entry.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let crv = entry.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty != "OKP" || crv != "Ed25519" {
                continue;
            }
            let Some(kid) = entry.get("kid").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(x_b64) = entry.get("x").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(pub_bytes) = URL_SAFE_NO_PAD.decode(x_b64.trim()) else {
                continue;
            };
            if pub_bytes.len() != 32 {
                continue;
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&pub_bytes);
            if let Ok(vk) = VerifyingKey::from_bytes(&key_arr) {
                guard.insert(kid.to_string(), vk);
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn register_key(&self, kid: &str, key: VerifyingKey) {
        self.keys.write().insert(kid.to_string(), key);
    }

    pub fn resolve_key(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys.read().get(kid).copied()
    }
}

pub struct NonceReplayCache {
    ttl: Duration,
    entries: Mutex<HashMap<String, Instant>>,
}

impl NonceReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_record(&self, nonce: &str) -> Result<(), String> {
        let trimmed = nonce.trim();
        if trimmed.is_empty() {
            return Err("Missing or empty nonce".to_string());
        }
        let now = Instant::now();
        let mut guard = self.entries.lock();
        guard.retain(|_, exp| *exp > now);
        if guard.contains_key(trimmed) {
            return Err(format!("Replay detected for single-use nonce '{trimmed}'"));
        }
        guard.insert(trimmed.to_string(), now + self.ttl);
        Ok(())
    }
}

const WINDOW_24H_MS: u64 = 86_400_000;

/// 24-hour sliding-window cumulative scalar tracker for stateful CBF barriers.
pub struct Cumulative24hTracker {
    samples: Mutex<VecDeque<(u64, f64)>>,
}

impl Default for Cumulative24hTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Cumulative24hTracker {
    pub fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
        }
    }

    pub fn record_at(&self, timestamp_ms: u64, amount: f64) -> f64 {
        let mut guard = self.samples.lock();
        let cutoff = timestamp_ms.saturating_sub(WINDOW_24H_MS);
        while let Some(&(ts, _)) = guard.front() {
            if ts < cutoff {
                guard.pop_front();
            } else {
                break;
            }
        }
        if amount.is_finite() && amount > 0.0 {
            guard.push_back((timestamp_ms, amount));
        }
        guard.iter().map(|(_, v)| *v).sum()
    }

    pub fn total_at(&self, timestamp_ms: u64) -> f64 {
        let mut guard = self.samples.lock();
        let cutoff = timestamp_ms.saturating_sub(WINDOW_24H_MS);
        while let Some(&(ts, _)) = guard.front() {
            if ts < cutoff {
                guard.pop_front();
            } else {
                break;
            }
        }
        guard.iter().map(|(_, v)| *v).sum()
    }
}

/// 24-hour sliding-window distinct-key accumulator for cross-tenant fan-out CBF barriers.
pub struct KeyedCumulative24hTracker {
    entries: Mutex<HashMap<String, u64>>,
}

impl Default for KeyedCumulative24hTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyedCumulative24hTracker {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_key_at(&self, timestamp_ms: u64, key: &str) -> usize {
        let mut guard = self.entries.lock();
        let cutoff = timestamp_ms.saturating_sub(WINDOW_24H_MS);
        guard.retain(|_, ts| *ts >= cutoff);
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            guard.insert(trimmed.to_string(), timestamp_ms);
        }
        guard.len()
    }

    pub fn distinct_count_at(&self, timestamp_ms: u64) -> usize {
        let mut guard = self.entries.lock();
        let cutoff = timestamp_ms.saturating_sub(WINDOW_24H_MS);
        guard.retain(|_, ts| *ts >= cutoff);
        guard.len()
    }
}

// =============================================================================
// 4. CAGE Substrate DTOs & State
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineRequest {
    pub workload_id: String,
    #[serde(default)]
    pub target_pid: Option<u32>,
    pub trigger_reason: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineReceiptResponse {
    pub status: String,
    pub quarantined: bool,
    pub enforcement_plane: String,
    pub rule_id: String,
    pub quarantined_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_digest: Option<String>,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineReleaseRequest {
    pub workload_id: String,
    pub quorum_approval_digest: String,
    pub quorum_count: usize,
    pub nonce: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineReleaseReceiptResponse {
    pub released: bool,
    pub enforcement_plane: String,
    pub epoch_before: u64,
    pub epoch_after: u64,
    pub outcome: String,
    pub released_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_digest: Option<String>,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageAttestationResponse {
    pub attestation_type: String,
    pub ring0_posture: String,
    pub tpm_pcr_quote: String,
    pub pcr_values: BTreeMap<String, String>,
    pub timestamp_utc: String,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageConformalBaselineResponse {
    pub region: String,
    pub alpha: f64,
    pub calibration_size: usize,
    pub nonconformity_threshold: f64,
    pub timestamp_utc: String,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageConformalValidateRequest {
    pub scores: Vec<f64>,
    #[serde(default)]
    pub alpha: Option<f64>,
    #[serde(default)]
    pub action: Option<String>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageConformalValidateResponse {
    pub admitted: bool,
    pub p_value: f64,
    pub alpha: f64,
    pub voter_consensus: String,
    pub timestamp_utc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_digest: Option<String>,
    pub kid: String,
    pub signature: String,
}

fn substrate_error(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    let msg = message.into();
    (
        status,
        Json(json!({
            "error": true,
            "code": code,
            "message": msg,
        })),
    )
}

pub struct CageSubstrateState {
    pub signing_key: Arc<SigningKey>,
    pub ed25519_kid: String,
    pub jwks_cache: Value,
    pub cage_key_manifest: Arc<CageKeyManifestResolver>,
    pub replay_cache: Arc<NonceReplayCache>,
    pub journal: Arc<QuarantineJournal>,
    pub egress_bytes_24h: Arc<Cumulative24hTracker>,
    pub cross_tenant_targets_24h: Arc<KeyedCumulative24hTracker>,
}

impl Default for CageSubstrateState {
    fn default() -> Self {
        Self::new()
    }
}

impl CageSubstrateState {
    pub fn new() -> Self {
        let state_dir = if let Ok(dir) = std::env::var("OSOOSI_CAGE_JOURNAL_DIR") {
            PathBuf::from(dir)
        } else if cfg!(test) || osoosi_core::wfp::is_cargo_test_simulation_mode() {
            std::env::temp_dir().join(format!("osoosi_cage_substrate_{}", uuid::Uuid::new_v4()))
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("database")
        };
        Self::with_state_dir(state_dir)
    }

    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let ed25519_kid = hex::encode(Sha256::digest(pub_bytes));
        let x_b64 = URL_SAFE_NO_PAD.encode(pub_bytes);

        let jwks_cache = json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": ed25519_kid,
                    "x": x_b64,
                    "use": "sig",
                    "alg": "EdDSA"
                }
            ]
        });

        let cage_key_manifest = Arc::new(CageKeyManifestResolver::new());
        let replay_cache = Arc::new(NonceReplayCache::new(Duration::from_secs(300)));
        let journal = Arc::new(QuarantineJournal::new(
            state_dir,
            Arc::clone(&signing_key),
            ed25519_kid.clone(),
        ));

        Self {
            signing_key,
            ed25519_kid,
            jwks_cache,
            cage_key_manifest,
            replay_cache,
            journal,
            egress_bytes_24h: Arc::new(Cumulative24hTracker::new()),
            cross_tenant_targets_24h: Arc::new(KeyedCumulative24hTracker::new()),
        }
    }
}

// =============================================================================
// 5. Six CAGE Layer 3 `actuator_04` Substrate Endpoint Handlers
// =============================================================================

/// 1. `GET /.well-known/jwks.json`
pub async fn handle_jwks(State(state): State<DashboardState>) -> Json<Value> {
    Json(state.cage_substrate.jwks_cache.clone())
}

/// 2. `GET /v1/cage/normative-baseline/:region`
pub async fn handle_conformal_baseline(
    State(state): State<DashboardState>,
    Path(region): Path<String>,
) -> Result<Json<CageConformalBaselineResponse>, (StatusCode, Json<Value>)> {
    let sub = &state.cage_substrate;
    let clean_region = if region.trim().is_empty() {
        "global".to_string()
    } else {
        region.trim().to_string()
    };
    let now_utc = Utc::now().to_rfc3339();
    let unsigned_baseline = json!({
        "region": clean_region,
        "alpha": 0.05,
        "calibration_size": 500,
        "nonconformity_threshold": 4.25,
        "timestamp_utc": now_utc,
        "kid": sub.ed25519_kid
    });

    let canonical_bytes = canonicalize_substrate_jcs(&unsigned_baseline).map_err(|e| {
        substrate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Baseline JCS canonicalization failed: {e}"),
        )
    })?;
    let mut preimage = b"CAGE_CONFORMAL_BASELINE_V1:".to_vec();
    preimage.extend_from_slice(&canonical_bytes);

    let sig = sub.signing_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(Json(CageConformalBaselineResponse {
        region: clean_region,
        alpha: 0.05,
        calibration_size: 500,
        nonconformity_threshold: 4.25,
        timestamp_utc: now_utc,
        kid: sub.ed25519_kid.clone(),
        signature: sig_b64,
    }))
}

/// 3. `GET /v1/cage/attest`
pub async fn handle_cage_attest(
    State(state): State<DashboardState>,
) -> Result<Json<CageAttestationResponse>, (StatusCode, Json<Value>)> {
    let sub = &state.cage_substrate;
    let boot = crate::TpmPcrBootMeasurements::query_live();
    let kc = osoosi_core::killchain::get_killchain_status();

    let mut pcr_values = BTreeMap::new();
    pcr_values.insert("0".to_string(), boot.pcr0_firmware_hex.clone());
    pcr_values.insert("2".to_string(), boot.pcr2_option_rom_hex.clone());
    pcr_values.insert("4".to_string(), boot.pcr4_boot_manager_hex.clone());
    pcr_values.insert("7".to_string(), boot.pcr7_secure_boot_hex.clone());

    let mut quote_hasher = Sha256::new();
    quote_hasher.update(b"OSHOOSI_TPM2_PCR_QUOTE_V1:");
    for (idx, val) in &pcr_values {
        quote_hasher.update(idx.as_bytes());
        quote_hasher.update(b"=");
        quote_hasher.update(val.as_bytes());
        quote_hasher.update(b";");
    }
    let tpm_pcr_quote = hex::encode(quote_hasher.finalize());

    let ring0_posture = if kc.isolated {
        "ISOLATED_RING0_ENFORCED".to_string()
    } else if boot.uefi_secure_boot_enabled {
        "ACTIVE_SECURE_BOOT_VERIFIED".to_string()
    } else {
        "ACTIVE_USERMODE_GUARD".to_string()
    };

    let now_utc = Utc::now().to_rfc3339();
    let unsigned_attestation = json!({
        "attestation_type": "HOST_TPM_PCR",
        "ring0_posture": ring0_posture,
        "tpm_pcr_quote": tpm_pcr_quote,
        "pcr_values": pcr_values,
        "timestamp_utc": now_utc,
        "kid": sub.ed25519_kid
    });

    let canonical_bytes = canonicalize_substrate_jcs(&unsigned_attestation).map_err(|e| {
        substrate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Attestation JCS canonicalization failed: {e}"),
        )
    })?;
    let mut preimage = b"CAGE_ATTESTATION_RECEIPT_V1:".to_vec();
    preimage.extend_from_slice(&canonical_bytes);

    let sig = sub.signing_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(Json(CageAttestationResponse {
        attestation_type: "HOST_TPM_PCR".to_string(),
        ring0_posture,
        tpm_pcr_quote,
        pcr_values,
        timestamp_utc: now_utc,
        kid: sub.ed25519_kid.clone(),
        signature: sig_b64,
    }))
}

/// 4. `POST /v1/cage/conformal/validate`
pub async fn handle_conformal_validate(
    State(state): State<DashboardState>,
    body_bytes: Bytes,
) -> Result<Json<CageConformalValidateResponse>, (StatusCode, Json<Value>)> {
    let sub = &state.cage_substrate;
    let parsed_val: Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("Invalid request JSON: {e}"),
        )
    })?;
    let canonical_body = canonicalize_substrate_jcs(&parsed_val).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("JCS canonicalization error: {e}"),
        )
    })?;
    let req: CageConformalValidateRequest = serde_json::from_value(parsed_val).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("Failed to parse conformal validation request: {e}"),
        )
    })?;

    if req.scores.is_empty() {
        return Err(substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Conformal validation scores vector cannot be empty",
        ));
    }
    if req.scores.iter().any(|s| !s.is_finite()) {
        return Err(substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Conformal validation scores must be finite numbers",
        ));
    }

    sub.replay_cache
        .check_and_record(&req.nonce)
        .map_err(|e| substrate_error(StatusCode::CONFLICT, "REPLAY_DETECTED", e))?;

    let alpha = req.alpha.unwrap_or(0.05);
    let p_value = osoosi_behavioral::compute_normative_conformal_p_value(&req.scores);
    let admitted = p_value > alpha;

    // Multi-voter consensus combining conformal gate with active DLP/breakout action screening
    let action_lower = req
        .action
        .as_deref()
        .unwrap_or("cage_action")
        .to_ascii_lowercase();
    let lethal_action_signal = action_lower.contains("privilege_escalation")
        || action_lower.contains("mimikatz")
        || action_lower.contains("kernel_bypass");

    let voter_consensus = if admitted && !lethal_action_signal {
        "CONSENSUS_ALLOW".to_string()
    } else {
        "CONSENSUS_DENY".to_string()
    };

    let now_utc = Utc::now().to_rfc3339();
    let envelope_digest = hex::encode(Sha256::digest(&canonical_body));
    let unsigned_resp = json!({
        "admitted": admitted,
        "p_value": p_value,
        "alpha": alpha,
        "voter_consensus": voter_consensus,
        "timestamp_utc": now_utc,
        "envelope_digest": envelope_digest,
        "kid": sub.ed25519_kid
    });

    let canonical_bytes = canonicalize_substrate_jcs(&unsigned_resp).map_err(|e| {
        substrate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Validation JCS failed: {e}"),
        )
    })?;
    let mut preimage = b"CAGE_CONFORMAL_VALIDATION_V1:".to_vec();
    preimage.extend_from_slice(&canonical_bytes);

    let sig = sub.signing_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(Json(CageConformalValidateResponse {
        admitted,
        p_value,
        alpha,
        voter_consensus,
        timestamp_utc: now_utc,
        envelope_digest: Some(envelope_digest),
        kid: sub.ed25519_kid.clone(),
        signature: sig_b64,
    }))
}

/// 5. `POST /v1/cage/quarantine`
pub async fn handle_cage_quarantine(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<CageQuarantineReceiptResponse>, (StatusCode, Json<Value>)> {
    let sub = &state.cage_substrate;
    let assertion_b64 = headers
        .get("X-CAGE-Quarantine-Assertion")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            substrate_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Missing X-CAGE-Quarantine-Assertion header",
            )
        })?;

    let signer_kid = headers
        .get("X-CAGE-Signer-Kid")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            substrate_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Missing X-CAGE-Signer-Kid header",
            )
        })?;

    let parsed_val: Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("Invalid request JSON: {e}"),
        )
    })?;
    let canonical_body = canonicalize_substrate_jcs(&parsed_val).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("JCS canonicalization error: {e}"),
        )
    })?;
    let mut preimage = b"CAGE_QUARANTINE_ASSERTION_V1:".to_vec();
    preimage.extend_from_slice(&canonical_body);

    let verifying_key = sub
        .cage_key_manifest
        .resolve_key(signer_kid.trim())
        .ok_or_else(|| {
            substrate_error(
                StatusCode::FORBIDDEN,
                "UNKNOWN_SIGNER_KID",
                format!("Unrecognized CAGE kid: {}", signer_kid.trim()),
            )
        })?;

    let sig_bytes = URL_SAFE_NO_PAD.decode(assertion_b64.trim()).map_err(|e| {
        substrate_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_SIGNATURE",
            format!("Malformed base64url signature: {e}"),
        )
    })?;
    if sig_bytes.len() != 64 {
        return Err(substrate_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_SIGNATURE",
            "Signature must be exactly 64 bytes",
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(&preimage, &signature).map_err(|e| {
        substrate_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_SIGNATURE",
            format!("Ed25519 signature verification failed: {e}"),
        )
    })?;

    let req: CageQuarantineRequest = serde_json::from_value(parsed_val).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("Failed to parse QuarantineDirective: {e}"),
        )
    })?;

    sub.replay_cache
        .check_and_record(&req.nonce)
        .map_err(|e| substrate_error(StatusCode::CONFLICT, "REPLAY_DETECTED", e))?;

    let rule_id = req
        .rule_id
        .unwrap_or_else(|| "RULE-SC-7-CBF-LETHAL".to_string());
    let reason = format!(
        "[CAGE-QUARANTINE:{}] workload={} reason={}",
        rule_id, req.workload_id, req.trigger_reason
    );

    if let Err(e) = osoosi_core::killchain::engage_killchain_isolation(
        "CAGE-Governor",
        &reason,
        true,
        false,
        true,
    )
    .await
    {
        warn!(
            "⚠️ [CAGE-SUBSTRATE] Kernel isolation returned degraded status for '{}': {}",
            req.workload_id, e
        );
    }

    if let Some(pid) = req.target_pid {
        if pid > 0 && !osoosi_core::wfp::is_cargo_test_simulation_mode() {
            let _ = osoosi_core::killchain::suspend_process_by_pid(pid);
            info!("❄️ [CAGE-SUBSTRATE] Suspended target PID {}", pid);
        }
    }

    let now_utc = Utc::now().to_rfc3339();
    let lease = QuarantineLease {
        workload_id: req.workload_id.clone(),
        target_pid: req.target_pid,
        trigger_reason: req.trigger_reason.clone(),
        rule_id: rule_id.clone(),
        quarantined_at: now_utc.clone(),
        expires_at_unix_ms: None,
        nonce: req.nonce.clone(),
    };
    sub.journal.record_quarantine(lease).map_err(|e| {
        substrate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "JOURNAL_SEAL_FAILED",
            format!("Failed to record quarantine lease in sealed journal: {e}"),
        )
    })?;

    let envelope_digest = hex::encode(Sha256::digest(&canonical_body));
    let mut unsigned_receipt = json!({
        "status": "QUARANTINED",
        "quarantined": true,
        "enforcement_plane": "HOST_OS_KERNEL",
        "rule_id": rule_id,
        "quarantined_at": now_utc,
        "envelope_digest": envelope_digest,
        "kid": sub.ed25519_kid
    });
    if let Some(pid) = req.target_pid {
        unsigned_receipt["target_pid"] = json!(pid);
    }

    let canonical_receipt = canonicalize_substrate_jcs(&unsigned_receipt).map_err(|e| {
        substrate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Quarantine receipt JCS canonicalization failed: {e}"),
        )
    })?;
    let mut receipt_preimage = b"CAGE_QUARANTINE_RECEIPT_V1:".to_vec();
    receipt_preimage.extend_from_slice(&canonical_receipt);

    let receipt_sig = sub.signing_key.sign(&receipt_preimage);
    let receipt_sig_b64 = URL_SAFE_NO_PAD.encode(receipt_sig.to_bytes());

    Ok(Json(CageQuarantineReceiptResponse {
        status: "QUARANTINED".to_string(),
        quarantined: true,
        enforcement_plane: "HOST_OS_KERNEL".to_string(),
        rule_id,
        quarantined_at: now_utc,
        target_pid: req.target_pid,
        envelope_digest: Some(envelope_digest),
        kid: sub.ed25519_kid.clone(),
        signature: receipt_sig_b64,
    }))
}

/// 6. `POST /v1/cage/release`
pub async fn handle_cage_release(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<CageQuarantineReleaseReceiptResponse>, (StatusCode, Json<Value>)> {
    let sub = &state.cage_substrate;
    let release_sig_b64 = headers
        .get("X-CAGE-Quarantine-Release")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            substrate_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Missing X-CAGE-Quarantine-Release header",
            )
        })?;

    let signer_kid = headers
        .get("X-CAGE-Signer-Kid")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            substrate_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Missing X-CAGE-Signer-Kid header",
            )
        })?;

    let parsed_val: Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("Invalid request JSON: {e}"),
        )
    })?;
    let canonical_body = canonicalize_substrate_jcs(&parsed_val).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("JCS canonicalization error: {e}"),
        )
    })?;
    let mut preimage = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage.extend_from_slice(&canonical_body);

    let verifying_key = sub
        .cage_key_manifest
        .resolve_key(signer_kid.trim())
        .ok_or_else(|| {
            substrate_error(
                StatusCode::FORBIDDEN,
                "UNKNOWN_SIGNER_KID",
                format!("Unrecognized CAGE kid: {}", signer_kid.trim()),
            )
        })?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(release_sig_b64.trim())
        .map_err(|e| {
            substrate_error(
                StatusCode::UNAUTHORIZED,
                "INVALID_SIGNATURE",
                format!("Malformed base64url signature: {e}"),
            )
        })?;
    if sig_bytes.len() != 64 {
        return Err(substrate_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_SIGNATURE",
            "Signature must be exactly 64 bytes",
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(&preimage, &signature).map_err(|e| {
        substrate_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_SIGNATURE",
            format!("Ed25519 signature verification failed: {e}"),
        )
    })?;

    let req: CageQuarantineReleaseRequest = serde_json::from_value(parsed_val).map_err(|e| {
        substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("Failed to parse QuarantineReleaseDirective: {e}"),
        )
    })?;

    if req.quorum_count < 2 {
        return Err(substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!(
                "Quorum release requires quorum_count >= 2, received {}",
                req.quorum_count
            ),
        ));
    }
    let digest = req.quorum_approval_digest.trim();
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(substrate_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "quorum_approval_digest must be a 64-character hex SHA-256 string",
        ));
    }

    sub.replay_cache
        .check_and_record(&req.nonce)
        .map_err(|e| substrate_error(StatusCode::CONFLICT, "REPLAY_DETECTED", e))?;

    let (epoch_before, epoch_after) = sub
        .journal
        .advance_generation_epoch(&req.workload_id)
        .map_err(|e| {
            substrate_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "JOURNAL_SEAL_FAILED",
                format!("Failed to advance generation epoch: {e}"),
            )
        })?;

    info!(
        "🔄 [CAGE-SUBSTRATE] Monotonically advanced epoch for '{}': Gen {} -> Gen {}",
        req.workload_id, epoch_before, epoch_after
    );

    let removed_lease = sub
        .journal
        .release_quarantine(&req.workload_id)
        .map_err(|e| {
            substrate_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "JOURNAL_SEAL_FAILED",
                format!("Failed to release quarantine lease: {e}"),
            )
        })?;

    if let Some(lease) = removed_lease {
        if let Some(pid) = lease.target_pid {
            if pid > 0 && !osoosi_core::wfp::is_cargo_test_simulation_mode() {
                let _ = osoosi_core::killchain::resume_process_by_pid(pid);
                info!("☀️ [CAGE-SUBSTRATE] Resumed previously frozen PID {}", pid);
            }
        }
    }

    if sub.journal.unexpired_leases().is_empty() {
        let _ = osoosi_core::killchain::disarm_killchain_isolation(
            "CAGE-Quorum-Release",
            &format!(
                "Quorum-governed release approved for workload '{}' (quorum count: {})",
                req.workload_id, req.quorum_count
            ),
        )
        .await;
        info!("🔓 [CAGE-SUBSTRATE] Zero remaining leases; host OS kernel isolation lifted");
    }

    let now_utc = Utc::now().to_rfc3339();
    let envelope_digest = hex::encode(Sha256::digest(&canonical_body));
    let unsigned_receipt = json!({
        "released": true,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": epoch_before,
        "epoch_after": epoch_after,
        "outcome": "RELEASED",
        "released_at": now_utc,
        "envelope_digest": envelope_digest,
        "kid": sub.ed25519_kid
    });

    let canonical_receipt = canonicalize_substrate_jcs(&unsigned_receipt).map_err(|e| {
        substrate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Release receipt JCS canonicalization failed: {e}"),
        )
    })?;
    let mut receipt_preimage = b"CAGE_QUARANTINE_RELEASE_RECEIPT_V1:".to_vec();
    receipt_preimage.extend_from_slice(&canonical_receipt);

    let receipt_sig = sub.signing_key.sign(&receipt_preimage);
    let receipt_sig_b64 = URL_SAFE_NO_PAD.encode(receipt_sig.to_bytes());

    Ok(Json(CageQuarantineReleaseReceiptResponse {
        released: true,
        enforcement_plane: "HOST_OS_KERNEL".to_string(),
        epoch_before,
        epoch_after,
        outcome: "RELEASED".to_string(),
        released_at: now_utc,
        envelope_digest: Some(envelope_digest),
        kid: sub.ed25519_kid.clone(),
        signature: receipt_sig_b64,
    }))
}

pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/.well-known/jwks.json", get(handle_jwks))
        .route(
            "/v1/cage/normative-baseline/:region",
            get(handle_conformal_baseline),
        )
        .route(
            "/api/v1/cage/normative-baseline/:region",
            get(handle_conformal_baseline),
        )
        .route("/v1/cage/attest", get(handle_cage_attest))
        .route("/api/v1/cage/attest", get(handle_cage_attest))
        .route(
            "/v1/cage/conformal/validate",
            post(handle_conformal_validate),
        )
        .route(
            "/api/v1/cage/conformal/validate",
            post(handle_conformal_validate),
        )
        .route("/v1/cage/quarantine", post(handle_cage_quarantine))
        .route("/api/v1/cage/quarantine", post(handle_cage_quarantine))
        .route("/v1/cage/release", post(handle_cage_release))
        .route("/api/v1/cage/release", post(handle_cage_release))
}
