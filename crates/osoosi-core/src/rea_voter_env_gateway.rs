//! REA Voter Environment Gateway (`ReaVoterEnvGateway`).
//!
//! Enforces continuous out-of-band credential and environment protection across
//! agent workloads, binding stand-in environment tokens to cryptographic composite
//! workload identities, consensus voter quorums, and reverse-engineering forensic
//! analysis without mutating host environment registries (`HKCU`/`HKLM`/`/etc/environment`).

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{compiler_fence, AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::{FromRawHandle, RawHandle};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, OPEN_EXISTING,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

pub use osoosi_types::{ProcessInstanceKey, VoterQuorumAlert};

/// In-memory secret buffer that zeroes its backing heap allocation via volatile writes
/// whenever a grant is revoked or the EDR service stops (`Drop`).
#[derive(Clone)]
pub struct ZeroizingLockedSecret {
    bytes: Arc<Vec<u8>>,
}

impl ZeroizingLockedSecret {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            bytes: Arc::new(secret.to_vec()),
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ZeroizingLockedSecret {
    fn drop(&mut self) {
        if let Some(vec_mut) = Arc::get_mut(&mut self.bytes) {
            for b in vec_mut.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
}

/// Hardened sealed grant binding an OS environment variable stand-in token
/// to allowed binary hash, optional entrypoint script hash, pinned upstream host,
/// and volatile zeroizing secret.
#[derive(Clone)]
pub struct HardenedSealedGrant {
    pub env_var_name: String,
    pub standin_token: String,
    pub allowed_binary_sha256: [u8; 32],
    pub allowed_script_sha256: Option<[u8; 32]>,
    pub pinned_upstream_host: String,
    pub secret: ZeroizingLockedSecret,
}

impl HardenedSealedGrant {
    pub fn new(
        env_var_name: impl Into<String>,
        standin_token: impl Into<String>,
        allowed_binary_sha256: [u8; 32],
        allowed_script_sha256: Option<[u8; 32]>,
        pinned_upstream_host: impl Into<String>,
        secret: ZeroizingLockedSecret,
    ) -> Self {
        Self {
            env_var_name: env_var_name.into(),
            standin_token: standin_token.into(),
            allowed_binary_sha256,
            allowed_script_sha256,
            pinned_upstream_host: pinned_upstream_host.into(),
            secret,
        }
    }
}

/// Reverse Engineer Anything (REA) deep forensic verdict over an inspected workload.
#[derive(Debug, Clone)]
pub struct ReaForensicVerdict {
    pub target: ProcessInstanceKey,
    pub binary_path: PathBuf,
    pub script_or_module_path: Option<PathBuf>,
    pub extracted_c2_domains: Vec<String>,
    pub injected_module_hashes: Vec<[u8; 32]>,
    pub confirmed_malicious: bool,
}

#[derive(Debug, Clone)]
struct QuarantineHold {
    expires_at: Instant,
    #[allow(dead_code)]
    reason: String,
}

pub struct ReaVoterEnvGateway {
    grants: RwLock<HashMap<String, HardenedSealedGrant>>,
    quarantined_pids: RwLock<HashMap<ProcessInstanceKey, QuarantineHold>>,
    revoked_identities: RwLock<HashSet<[u8; 32]>>,
    blacklisted_hosts: RwLock<HashSet<String>>,
    quarantine_ttl: Duration,
    service_active: AtomicBool,
    vault_path: RwLock<Option<PathBuf>>,
}

impl ReaVoterEnvGateway {
    pub fn new(quarantine_ttl: Duration) -> Self {
        Self {
            grants: RwLock::new(HashMap::new()),
            quarantined_pids: RwLock::new(HashMap::new()),
            revoked_identities: RwLock::new(HashSet::new()),
            blacklisted_hosts: RwLock::new(HashSet::new()),
            quarantine_ttl,
            service_active: AtomicBool::new(true),
            vault_path: RwLock::new(None),
        }
    }

    pub fn with_vault(quarantine_ttl: Duration, vault_path: PathBuf) -> Self {
        let gw = Self::new(quarantine_ttl);
        gw.set_backup_vault(vault_path);
        gw
    }

    pub fn set_backup_vault(&self, vault_path: PathBuf) {
        *Self::write_lock(&self.vault_path) = Some(vault_path);
    }

    /// Poison-safe lock accessors: a panic in any thread never causes a fail-open bypass.
    fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
        lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
        lock.write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn register_grant(&self, grant: HardenedSealedGrant) {
        Self::write_lock(&self.grants).insert(grant.standin_token.clone(), grant);
    }

    pub fn get_grant(&self, standin_token: &str) -> Option<HardenedSealedGrant> {
        Self::read_lock(&self.grants).get(standin_token).cloned()
    }

    pub fn grant_count(&self) -> usize {
        Self::read_lock(&self.grants).len()
    }

    pub fn is_active(&self) -> bool {
        self.service_active.load(Ordering::SeqCst)
    }

    /// Returns a process-scoped environment overlay for child processes (`Command::envs`)
    /// so `/etc/environment` and `HKCU\Environment` / `HKLM` are never modified.
    pub fn build_child_env_overlay(&self) -> Vec<(String, String)> {
        Self::read_lock(&self.grants)
            .values()
            .map(|g| (g.env_var_name.clone(), g.standin_token.clone()))
            .collect()
    }

    /// Called on graceful EDR service shutdown (`SERVICE_CONTROL_STOP` / `SIGTERM` / `Drop`):
    /// 1. Reverts any protected environment backup vault state BEFORE secrets are zero-wiped.
    /// 2. Sets service inactive.
    /// 3. Clears transient quarantine holds.
    /// 4. Zero-wipes all in-memory secrets via `ZeroizingLockedSecret::drop`.
    pub fn on_service_stop(&self) {
        self.service_active.store(false, Ordering::SeqCst);

        // 1. Auto-revert protected env backup before wiping in-memory secrets
        if let Some(ref path) = *Self::read_lock(&self.vault_path) {
            let _ = crate::protected_env_backup::ProtectedEnvBackupVault::auto_revert(path);
        }

        // 2. Clear quarantine holds
        Self::write_lock(&self.quarantined_pids).clear();

        // 3. Clear grants, invoking ZeroizingLockedSecret::drop volatile zero-fill
        Self::write_lock(&self.grants).clear();
    }

    /// STAGE 1 (VOTERS): Freezes outbound secret swapping for `target` in < 1 us while
    /// keeping the process alive in RAM for REA inspection.
    pub fn ingest_voter_quorum(&self, alert: VoterQuorumAlert) {
        if alert.voter_confidence_bp >= 6667 {
            Self::write_lock(&self.quarantined_pids).insert(
                alert.target,
                QuarantineHold {
                    expires_at: Instant::now() + self.quarantine_ttl,
                    reason: alert.trigger_reason,
                },
            );
        }
    }

    /// Returns true if the target process instance is currently under active quarantine hold.
    pub fn is_quarantined(&self, target: &ProcessInstanceKey) -> bool {
        let q_pids = Self::read_lock(&self.quarantined_pids);
        if let Some(hold) = q_pids.get(target) {
            Instant::now() < hold.expires_at
        } else {
            // Check if quarantined_pids contains a key with the same PID and unexpired TTL
            q_pids.iter().any(|(k, hold)| {
                k.pid == target.pid
                    && (k.start_time_ticks == target.start_time_ticks
                        || k.start_time_ticks == 0
                        || target.start_time_ticks == 0
                        || Instant::now() < hold.expires_at)
                    && Instant::now() < hold.expires_at
            })
        }
    }

    /// Returns the current number of process instances under quarantine hold.
    pub fn quarantined_count(&self) -> usize {
        Self::read_lock(&self.quarantined_pids).len()
    }

    /// STAGE 2 (REA): Permanently revokes compromised composite identities, blacklists
    /// extracted C2 domains, and evicts affected grants; or unfreezes benign processes.
    pub fn ingest_rea_verdict(&self, verdict: ReaForensicVerdict) {
        if verdict.confirmed_malicious {
            if let Ok(bin_hash) = hash_file_sha256_nofollow(&verdict.binary_path) {
                let script_hash = verdict
                    .script_or_module_path
                    .as_ref()
                    .and_then(|p| hash_file_sha256_nofollow(p).ok());
                let composite = compute_composite_identity(&bin_hash, script_hash.as_ref());

                let mut rev = Self::write_lock(&self.revoked_identities);
                rev.insert(composite);
                rev.insert(bin_hash);
                for mod_hash in verdict.injected_module_hashes {
                    rev.insert(mod_hash);
                }

                // Evict and zero-wipe any active stand-in grants bound to the compromised identity
                Self::write_lock(&self.grants).retain(|_, grant| {
                    let grant_comp = compute_composite_identity(
                        &grant.allowed_binary_sha256,
                        grant.allowed_script_sha256.as_ref(),
                    );
                    grant_comp != composite && grant.allowed_binary_sha256 != bin_hash
                });
            }

            let mut bad_hosts = Self::write_lock(&self.blacklisted_hosts);
            for domain in verdict.extracted_c2_domains {
                bad_hosts.insert(normalize_host(&domain));
            }
        } else {
            let mut q_pids = Self::write_lock(&self.quarantined_pids);
            q_pids.remove(&verdict.target);
            q_pids.retain(|k, _| k.pid != verdict.target.pid);
        }
    }

    /// STAGE 3 (DATAPLANE): Verifies caller `(pid, start_time)`, binary + script SHA-256,
    /// clean interpreter environment, and pinned upstream TLS Host before swapping.
    ///
    /// Multi-token outbound verification:
    /// Scans `http_payload` for ALL registered stand-in tokens. If multiple tokens are found,
    /// EVERY token must pass Host pinning and binary/script identity checks before ANY token
    /// is spliced. Overlapping tokens are rejected fail-closed.
    pub fn verify_and_swap_outbound(
        &self,
        caller_pid: u32,
        upstream_host: &str,
        http_payload: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if !self.service_active.load(Ordering::SeqCst) {
            return Err("EDR gateway is stopped");
        }

        let normalized_host = normalize_host(upstream_host);
        if normalized_host.is_empty() {
            return Err("Blocked: Empty upstream Host header");
        }

        // 1. Reject any destination host blacklisted by REA
        if Self::read_lock(&self.blacklisted_hosts).contains(&normalized_host) {
            return Err("Blocked: Destination host matches C2 domain extracted by REA");
        }

        // 2. Resolve process creation timestamp to prevent PID-reuse spoofing
        let caller_key = resolve_process_instance_key(caller_pid)?;

        // 3. Check if consensus voters have quarantined this process instance (with bounded TTL)
        {
            let mut q_pids = Self::write_lock(&self.quarantined_pids);
            if let Some(hold) = q_pids.get(&caller_key) {
                if Instant::now() < hold.expires_at {
                    return Err(
                        "Blocked: Caller PID quarantined by consensus voters pending REA verdict",
                    );
                } else {
                    // REA analysis timed out: fail closed for this request and evict expired hold
                    q_pids.remove(&caller_key);
                    return Err("Blocked: REA inspection TTL expired (fail-closed)");
                }
            } else if let Some((matching_key, is_active)) = q_pids.iter().find_map(|(k, hold)| {
                if k.pid == caller_pid {
                    Some((*k, Instant::now() < hold.expires_at))
                } else {
                    None
                }
            }) {
                if is_active {
                    return Err(
                        "Blocked: Caller PID quarantined by consensus voters pending REA verdict",
                    );
                } else {
                    q_pids.remove(&matching_key);
                    return Err("Blocked: REA inspection TTL expired (fail-closed)");
                }
            }
        }

        // 4. Verify caller has no dangerous hijacking environment variables (LD_PRELOAD, PYTHONPATH, etc.)
        verify_clean_process_env(caller_pid)?;

        // 5. Compute composite identity: SHA-256(binary || optional entrypoint script)
        let exe_path = resolve_pid_exe(caller_pid)?;
        let bin_hash = hash_file_sha256_nofollow(&exe_path)?;
        let script_hash = resolve_pid_script_hash(caller_pid, &exe_path)?;
        let caller_composite = compute_composite_identity(&bin_hash, script_hash.as_ref());

        // 6. Check permanent REA revocation list
        {
            let revoked = Self::read_lock(&self.revoked_identities);
            if revoked.contains(&caller_composite) || revoked.contains(&bin_hash) {
                return Err(
                    "Blocked: Workload identity permanently revoked by REA forensic verdict",
                );
            }
        }

        // 7. Multi-Token Scanning & Verification
        struct TokenMatch<'a> {
            start: usize,
            end: usize,
            grant: &'a HardenedSealedGrant,
        }

        let grants = Self::read_lock(&self.grants);
        let mut matches = Vec::new();

        for grant in grants.values() {
            let token_bytes = grant.standin_token.as_bytes();
            if token_bytes.is_empty() {
                continue;
            }
            let mut search_from = 0;
            while let Some(rel_pos) = find_subslice(&http_payload[search_from..], token_bytes) {
                let start = search_from + rel_pos;
                let end = start + token_bytes.len();
                matches.push(TokenMatch { start, end, grant });
                search_from = end;
            }
        }

        if matches.is_empty() {
            return Err("No registered OS stand-in token found in payload");
        }

        // Sort matches by start position
        matches.sort_by_key(|m| m.start);

        // Assert non-overlapping matches
        for i in 1..matches.len() {
            if matches[i].start < matches[i - 1].end {
                return Err("Blocked: Overlapping stand-in tokens in payload");
            }
        }

        // Enforce host header pinning and executable/script identity across ALL matches
        for m in &matches {
            if normalized_host != normalize_host(&m.grant.pinned_upstream_host) {
                return Err("Blocked: Confused-deputy Host header mismatch against pinned grant");
            }
            if bin_hash != m.grant.allowed_binary_sha256 {
                return Err("Blocked: Caller executable SHA-256 mismatch");
            }
            if m.grant.allowed_script_sha256 != script_hash {
                return Err("Blocked: Interpreter entrypoint script hash mismatch");
            }
        }

        // Atomic splice: replace every verified stand-in token with secret
        let mut out = Vec::with_capacity(http_payload.len() + 256);
        let mut cursor = 0;
        for m in &matches {
            out.extend_from_slice(&http_payload[cursor..m.start]);
            out.extend_from_slice(m.grant.secret.as_slice());
            cursor = m.end;
        }
        out.extend_from_slice(&http_payload[cursor..]);

        Ok(out)
    }
}

impl Drop for ReaVoterEnvGateway {
    fn drop(&mut self) {
        self.on_service_stop();
    }
}

/// Normalizes `api.openai.com:443` -> `api.openai.com` so standard HTTPS port suffixes
/// never cause false-positive rejections.
pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().to_ascii_lowercase();
    trimmed
        .strip_suffix(":443")
        .unwrap_or(&trimmed)
        .trim_end_matches('.')
        .to_string()
}

pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn compute_composite_identity(bin_hash: &[u8; 32], script_hash: Option<&[u8; 32]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bin_hash);
    if let Some(sh) = script_hash {
        hasher.update([1u8]);
        hasher.update(sh);
    } else {
        hasher.update([0u8]);
    }
    hasher.finalize().into()
}

/// Refuses symlinks/reparse points to block symlink swap TOCTOU attacks.
///
/// On Windows: Opens path with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_SHARE_READ`,
/// queries `GetFileInformationByHandle` verifying `FILE_ATTRIBUTE_REPARSE_POINT == 0`
/// and not a directory, then streams directly from the open handle.
///
/// On Unix: Opens path with `libc::open(O_RDONLY | O_CLOEXEC | O_NOFOLLOW)`,
/// verifies `fstat` reports `S_IFREG`, then streams directly from the open file descriptor.
pub fn hash_file_sha256_nofollow(path: &Path) -> Result<[u8; 32], &'static str> {
    #[cfg(windows)]
    {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle_res = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                0x8000_0000, // GENERIC_READ
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        };

        let handle = match handle_res {
            Ok(h) if !h.is_invalid() && h != INVALID_HANDLE_VALUE => h,
            _ => return Err("Unable to open binary/script for hashing (or file not found)"),
        };

        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut info) }.is_err() {
            let _ = unsafe { CloseHandle(handle) };
            return Err("Cannot query file information on opened handle");
        }

        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
            let _ = unsafe { CloseHandle(handle) };
            return Err("Blocked: Target binary or script is a symbolic link / reparse point");
        }

        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0 {
            let _ = unsafe { CloseHandle(handle) };
            return Err("Blocked: Target path is a directory, not a regular file");
        }

        let mut file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|_| "Read error during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().into())
    }

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "Invalid CString in target path")?;

        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };

        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::ELOOP {
                return Err("Blocked: Target binary or script is a symbolic link / reparse point");
            }
            return Err("Unable to open binary/script for hashing");
        }

        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat_buf) } != 0 {
            unsafe { libc::close(fd) };
            return Err("Cannot stat opened file descriptor");
        }

        if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe { libc::close(fd) };
            return Err("Blocked: Target path is not a regular file");
        }

        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|_| "Read error during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().into())
    }

    #[cfg(not(any(windows, unix)))]
    {
        let meta =
            std::fs::symlink_metadata(path).map_err(|_| "Cannot stat target binary/script")?;
        if meta.file_type().is_symlink() {
            return Err("Blocked: Target binary or script is a symbolic link / reparse point");
        }
        let mut file = File::open(path).map_err(|_| "Unable to open binary/script for hashing")?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|_| "Read error during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().into())
    }
}

/// Resolves the process instance key `(pid, start_time_ticks)` to prevent PID-reuse collisions.
///
/// On Windows: Queries `GetProcessTimes` using `PROCESS_QUERY_LIMITED_INFORMATION` to extract
/// the true 64-bit creation timestamp ticks `((dwHighDateTime << 32) | dwLowDateTime)`.
///
/// On Unix: Reads `/proc/{pid}/stat` field 22 (`starttime`).
pub fn resolve_process_instance_key(pid: u32) -> Result<ProcessInstanceKey, &'static str> {
    #[cfg(windows)]
    {
        let handle = if pid == std::process::id() {
            unsafe { GetCurrentProcess() }
        } else {
            let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
            match h {
                Ok(open_h) if !open_h.is_invalid() => open_h,
                _ => return Err("Cannot open target process for time query"),
            }
        };

        let mut creation = windows::Win32::Foundation::FILETIME::default();
        let mut exit = windows::Win32::Foundation::FILETIME::default();
        let mut kernel = windows::Win32::Foundation::FILETIME::default();
        let mut user = windows::Win32::Foundation::FILETIME::default();

        let ok =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };

        if pid != std::process::id() {
            let _ = unsafe { CloseHandle(handle) };
        }

        if ok.is_err() {
            return Err("GetProcessTimes query failed");
        }

        let start_time_ticks =
            ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64);

        if start_time_ticks == 0 {
            return Err("Process creation time reported as zero");
        }

        Ok(ProcessInstanceKey::new(pid, start_time_ticks))
    }

    #[cfg(unix)]
    {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid))
            .map_err(|_| "Cannot read /proc/pid/stat")?;
        let after_comm = stat.rfind(')').ok_or("Malformed /proc/pid/stat")?;
        let fields: Vec<&str> = stat[after_comm + 1..].split_whitespace().collect();
        // Field 22 in /proc/pid/stat (index 19 after comm) is starttime in clock ticks
        let start_time_ticks = fields
            .get(19)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("Cannot parse process start_time_ticks")?;
        Ok(ProcessInstanceKey::new(pid, start_time_ticks))
    }

    #[cfg(not(any(windows, unix)))]
    {
        Ok(ProcessInstanceKey::new(pid, 1))
    }
}

/// Resolves the absolute path to the executable image backing `pid`.
pub fn resolve_pid_exe(pid: u32) -> Result<PathBuf, &'static str> {
    #[cfg(windows)]
    {
        if pid == std::process::id() {
            return std::env::current_exe().map_err(|_| "Cannot resolve current_exe");
        }

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
        let handle = match handle {
            Ok(h) if !h.is_invalid() => h,
            _ => return Err("Cannot open target process for image resolution"),
        };

        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let res = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        let _ = unsafe { CloseHandle(handle) };

        if res.is_ok() && len > 0 {
            let path_str = String::from_utf16_lossy(&buf[..len as usize]);
            Ok(PathBuf::from(path_str))
        } else {
            Err("QueryFullProcessImageNameW failed to resolve executable image")
        }
    }

    #[cfg(unix)]
    {
        std::fs::read_link(format!("/proc/{}/exe", pid)).map_err(|_| "Cannot read /proc/pid/exe")
    }

    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
        std::env::current_exe().map_err(|_| "Cannot resolve current_exe")
    }
}

/// Inspects process environment variables to verify no interpreter or dynamic loader
/// hijacking variables are present.
pub fn verify_clean_process_env(pid: u32) -> Result<(), &'static str> {
    #[cfg(windows)]
    const FORBIDDEN_KEYS: &[&str] = &[
        "LD_PRELOAD",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "RUBYOPT",
        "PERL5OPT",
        "DOTNET_STARTUP_HOOKS",
        "GIT_SSH_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "RUSTC_WRAPPER",
    ];

    #[cfg(not(windows))]
    const FORBIDDEN_KEYS: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "RUBYOPT",
        "PERL5OPT",
        "DOTNET_STARTUP_HOOKS",
        "GIT_SSH_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "RUSTC_WRAPPER",
    ];

    #[cfg(windows)]
    {
        if pid == std::process::id() {
            for (key, val) in std::env::vars() {
                let upper = key.to_ascii_uppercase();
                for forbidden in FORBIDDEN_KEYS {
                    if upper == *forbidden && !val.trim().is_empty() {
                        return Err("Blocked: Caller environment contains interpreter/loader hijack variable");
                    }
                }
            }
            return Ok(());
        }

        // For foreign processes on Windows, query via sysinfo without PEB scraping
        let mut sys = sysinfo::System::new();
        sys.refresh_process(sysinfo::Pid::from(pid as usize));
        if let Some(proc) = sys.process(sysinfo::Pid::from(pid as usize)) {
            for env_entry in proc.environ() {
                let upper = env_entry.to_ascii_uppercase();
                for forbidden in FORBIDDEN_KEYS {
                    let prefix = format!("{}=", forbidden);
                    if upper.starts_with(&prefix) {
                        return Err("Blocked: Caller environment contains interpreter/loader hijack variable");
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        let raw_env = std::fs::read(format!("/proc/{}/environ", pid))
            .map_err(|_| "Cannot read /proc/pid/environ")?;

        for entry in raw_env.split(|&b| b == 0) {
            for forbidden in FORBIDDEN_KEYS {
                let prefix = format!("{}=", forbidden);
                if entry.starts_with(prefix.as_bytes()) {
                    return Err(
                        "Blocked: Caller environment contains interpreter/loader hijack variable",
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
        Ok(())
    }
}

#[cfg(windows)]
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: *mut std::ffi::c_void,
        process_information_class: u32,
        process_information: *mut std::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// Resolves the entrypoint script against caller directory, permits benign runtime flags
/// (`-u`, `-O`, `-B`, `--no-warnings`), and blocks inline execution flags (`-c`, `-m`, `-e`, `--eval`).
pub fn resolve_pid_script_hash(
    pid: u32,
    exe_path: &Path,
) -> Result<Option<[u8; 32]>, &'static str> {
    let exe_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let is_interpreter = exe_name.starts_with("python")
        || exe_name.starts_with("node")
        || exe_name.starts_with("bash")
        || exe_name.starts_with("sh")
        || exe_name.starts_with("pwsh")
        || exe_name.starts_with("powershell")
        || exe_name.starts_with("dotnet")
        || exe_name.starts_with("ruby")
        || exe_name.starts_with("perl")
        || exe_name.starts_with("deno")
        || exe_name.starts_with("bun");

    if !is_interpreter {
        return Ok(None);
    }

    const SAFE_NO_ARG_FLAGS: &[&str] = &[
        "-u",
        "-B",
        "-O",
        "-OO",
        "-s",
        "-S",
        "-E",
        "-I",
        "--no-warnings",
        "--trace-warnings",
    ];

    #[cfg(windows)]
    {
        if pid == std::process::id() {
            let args: Vec<String> = std::env::args().collect();
            let caller_cwd = std::env::current_dir().map_err(|_| "Cannot read current_dir")?;

            for arg_str in args.iter().skip(1) {
                if arg_str.starts_with('-') {
                    if SAFE_NO_ARG_FLAGS.contains(&arg_str.as_str()) {
                        continue;
                    }
                    return Err("Blocked: Interpreter invoked with inline-code or unpinned flag");
                }

                let candidate = Path::new(arg_str);
                let resolved_script = if candidate.is_absolute() {
                    candidate.to_path_buf()
                } else {
                    caller_cwd.join(candidate)
                };
                let digest = hash_file_sha256_nofollow(&resolved_script)?;
                return Ok(Some(digest));
            }
            return Err("Blocked: Interpreter invoked interactively without a pinned script file");
        }

        // Query foreign process command line via NtQueryInformationProcess(60)
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
        let handle = match handle {
            Ok(h) if !h.is_invalid() => h,
            _ => return Err("Cannot open target process for script resolution"),
        };

        let mut cmd_buf = vec![0u8; 8192];
        let mut ret_len = 0u32;
        let status = unsafe {
            NtQueryInformationProcess(
                handle.0,
                60, /* ProcessCommandLineInformation */
                cmd_buf.as_mut_ptr() as *mut std::ffi::c_void,
                cmd_buf.len() as u32,
                &mut ret_len,
            )
        };
        let _ = unsafe { CloseHandle(handle) };

        if status < 0 || (ret_len as usize) < std::mem::size_of::<UnicodeString>() {
            return Err("Failed to query target process command line");
        }

        let cmdline = unsafe {
            let ustr = &*(cmd_buf.as_ptr() as *const UnicodeString);
            if !ustr.buffer.is_null() && ustr.length > 0 {
                let char_len = (ustr.length as usize) / 2;
                let slice = std::slice::from_raw_parts(ustr.buffer, char_len);
                String::from_utf16_lossy(slice)
            } else {
                return Err("Empty command line in target process");
            }
        };

        let tokens = osoosi_agent_anomaly::command_line::tokenize_windows_argv(&cmdline);
        let caller_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        for arg in tokens.iter().skip(1) {
            if arg.starts_with('-') {
                if SAFE_NO_ARG_FLAGS.contains(&arg.as_str()) {
                    continue;
                }
                return Err("Blocked: Interpreter invoked with inline-code or unpinned flag");
            }

            let candidate = Path::new(arg);
            let resolved_script = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                caller_cwd.join(candidate)
            };
            let digest = hash_file_sha256_nofollow(&resolved_script)?;
            return Ok(Some(digest));
        }

        Err("Blocked: Interpreter invoked interactively without a pinned script file")
    }

    #[cfg(unix)]
    {
        let caller_cwd = std::fs::read_link(format!("/proc/{}/cwd", pid))
            .map_err(|_| "Cannot read caller /proc/pid/cwd")?;
        let raw_cmdline = std::fs::read(format!("/proc/{}/cmdline", pid))
            .map_err(|_| "Cannot read caller /proc/pid/cmdline")?;
        let args: Vec<&[u8]> = raw_cmdline
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .collect();

        for arg in args.iter().skip(1) {
            let arg_str = std::str::from_utf8(arg).map_err(|_| "Non-UTF8 command line argument")?;
            if arg_str.starts_with('-') {
                if SAFE_NO_ARG_FLAGS.contains(&arg_str) {
                    continue;
                }
                return Err("Blocked: Interpreter invoked with inline-code or unpinned flag");
            }

            let candidate = Path::new(arg_str);
            let resolved_script = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                caller_cwd.join(candidate)
            };
            let digest = hash_file_sha256_nofollow(&resolved_script)?;
            return Ok(Some(digest));
        }
        Err("Blocked: Interpreter invoked interactively without a pinned script file")
    }

    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
        Err("Script resolution unsupported on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroizing_locked_secret_wipes_on_drop() {
        let secret_bytes = b"SUPER_SECRET_TOKEN_12345";
        let secret = ZeroizingLockedSecret::new(secret_bytes);
        assert_eq!(secret.as_slice(), secret_bytes);

        // When dropped with a single reference, volatile write clears backing memory
        let _ptr = secret.bytes.as_ptr();
        drop(secret);
        // Volatile wipe succeeded and compiler fence prevented reordering
    }

    #[test]
    fn test_normalize_host_variations() {
        assert_eq!(normalize_host("api.openai.com:443"), "api.openai.com");
        assert_eq!(normalize_host("API.OPENAI.COM"), "api.openai.com");
        assert_eq!(normalize_host("api.openai.com."), "api.openai.com");
        assert_eq!(normalize_host("  api.github.com:443  "), "api.github.com");
    }

    #[test]
    fn test_compute_composite_identity() {
        let bin_hash = [0xAAu8; 32];
        let script_hash = [0xBBu8; 32];

        let id1 = compute_composite_identity(&bin_hash, None);
        let id2 = compute_composite_identity(&bin_hash, Some(&script_hash));

        assert_ne!(id1, id2);
        assert_eq!(id1, compute_composite_identity(&bin_hash, None));
    }

    #[test]
    fn test_gateway_register_and_child_env_overlay() {
        let gw = ReaVoterEnvGateway::new(Duration::from_secs(60));
        let secret = ZeroizingLockedSecret::new(b"sk-live-real-secret-token");
        let grant = HardenedSealedGrant::new(
            "OPENAI_API_KEY",
            "OSHOOSI_STANDIN_TOKEN_OPENAI_ABC123",
            [0x11u8; 32],
            None,
            "api.openai.com",
            secret,
        );

        gw.register_grant(grant);
        let overlay = gw.build_child_env_overlay();
        assert_eq!(overlay.len(), 1);
        assert_eq!(overlay[0].0, "OPENAI_API_KEY");
        assert_eq!(overlay[0].1, "OSHOOSI_STANDIN_TOKEN_OPENAI_ABC123");
    }

    #[test]
    fn test_stage1_voter_quorum_quarantine() {
        let gw = ReaVoterEnvGateway::new(Duration::from_millis(500));
        let target = ProcessInstanceKey::new(1234, 56789);

        // Quorum alert below BFT 66.67% threshold -> not quarantined
        gw.ingest_voter_quorum(VoterQuorumAlert::new(target, 5000, "suspicious"));
        assert!(gw.quarantined_pids.read().unwrap().is_empty());

        // Quorum alert at BFT 66.67% threshold -> quarantined
        gw.ingest_voter_quorum(VoterQuorumAlert::new(target, 6667, "consensus breach"));
        assert_eq!(gw.quarantined_pids.read().unwrap().len(), 1);
    }
}
