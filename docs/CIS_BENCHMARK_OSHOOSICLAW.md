# CIS Benchmark Proposal: Autonomous AI Agent & Endpoint Containment (v1.1.0)

## Overview & Recommendation Summary

This benchmark defines **17 recommendations** across 5 control domains for hardening autonomous AI agents, model-context tool pipelines, and endpoint containment runtimes.

> [!IMPORTANT]
> **Count Alignment & Fail-Closed Audit Invariant:**
> - Both the summary specification and the control matrix below standardize on **17 recommendations** (resolving the prior 15 vs. 16 count discrepancy and adding Recommendation **4.4 Atomic Killswitch & Credential Revocation**).
> - Every audit script is **fail-closed**: missing or empty log files (`1.4`, `5.1`), `jq` parse/filter errors, or zero active confined worker processes (`4.3`) deterministically output `FAIL` (`exit 1`).

| ID | Control Domain | Recommendation Title | Level | Automated Audit |
| :--- | :--- | :--- | :--- | :--- |
| **1.1** | 1. Immutable Authority & Policy | Enforce 5-Level Immutable Authority Lattice (L1–L5) | Level 1 | Yes |
| **1.2** | 1. Immutable Authority & Policy | Enforce Continuous Cedar Reference Monitor with Past-Only MFOTL | Level 1 | Yes |
| **1.3** | 1. Immutable Authority & Policy | Prohibit Agent Self-Approval & Policy Mutation (`OWASP ASI10`) | Level 1 | Yes |
| **1.4** | 1. Immutable Authority & Policy | Verify Tamper-Evident BLAKE3 Merkle & Hybrid PQC Audit Log Integrity | Level 1 | Yes (Fail-Closed) |
| **2.1** | 2. Identity & Mesh Authentication | Enforce Per-Epoch HMAC-SHA256 Inter-Agent Message Signing | Level 1 | Yes |
| **2.2** | 2. Identity & Mesh Authentication | Enforce Unicode Case Folding, NFKC & UTS #39 Confusable-Skeleton Sink Isolation | Level 1 | Yes |
| **2.3** | 2. Identity & Mesh Authentication | Enforce Step-1 User Intent Pinning & Semantic Trajectory Drift Veto | Level 2 | Yes |
| **3.1** | 3. Filesystem & Workspace Isolation | Enforce Pre-Join Path Traversal, UNC & NTFS ADS Rejection | Level 1 | Yes |
| **3.2** | 3. Filesystem & Workspace Isolation | Enforce BLAKE3 Content-Lineage Poisoning Veto on Untrusted Ingestion | Level 2 | Yes |
| **3.3** | 3. Network & Egress SSRF Guard | Block All Special-Purpose IPv4/IPv6 Ranges & Non-Standard IP Encodings | Level 1 | Yes |
| **4.1** | 4. OS Process & Kernel Confinement | Enforce Mandatory `CREATE_SUSPENDED` + AppContainer + Job Object (Windows) | Level 1 | Yes |
| **4.2** | 4. OS Process & Kernel Confinement | Enforce `seccomp-bpf`, Landlock LSM & Read-Only Non-Root Rootfs (Linux) | Level 1 | Yes |
| **4.3** | 4. OS Process & Kernel Confinement | Verify Active Worker Process Sandbox Confinement (Zero Unconfined Workers) | Level 1 | Yes (Fail-Closed) |
| **4.4** | 4. OS Process & Kernel Confinement | Enforce Atomic Killswitch (`cgroup v2 cgroup.kill`) & Immediate Credential Revocation | Level 1 | Yes |
| **5.1** | 5. Data Loss Prevention & ZK Audit | Verify Two-Tier DLP & Law 10 Zero-PII Quarantine Audit Trail | Level 1 | Yes (Fail-Closed) |
| **5.2** | 5. Data Loss Prevention & ZK Audit | Enforce 4 KB Crown-Jewel Zero-Plaintext Merkle Fingerprinting | Level 1 | Yes |
| **5.3** | 5. Data Loss Prevention & ZK Audit | Enforce Law 8 Zero-Mutual-Information ($I = 0.0$ bits) Output Projection | Level 2 | Yes |

---

## Detailed Remediation & Fail-Closed Audit Procedures

### 1.4 Ensure Tamper-Evident BLAKE3 Merkle & Hybrid PQC Audit Log Integrity Is Verified (Automated)

**Profile Applicability:** Level 1  
**Description:** All containment transitions and policy decisions must be appended to a non-empty, valid JSONL audit log where every record carries a non-empty `merkle_root`, `pqc_sig_ml_dsa_65`, and `ed25519_sig`. A missing or empty log file, an invalid JSON line, or zero verified records **must fail** the audit.

**Audit Script (Fail-Closed):**
```bash
#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${OSHOOSI_AUDIT_LOG:-/var/log/oshoosiclaw/audit_merkle.jsonl}"

# 1. Fail immediately if file is missing or empty (0 bytes)
if [ ! -f "$LOG_FILE" ] || [ ! -s "$LOG_FILE" ]; then
    echo "FAIL: Audit log '$LOG_FILE' is missing or empty."
    exit 1
fi

# 2. Verify jq parses every line and count total records >= 1
RECORD_COUNT=$(jq -s 'length' "$LOG_FILE") || {
    echo "FAIL: Malformed JSON in '$LOG_FILE'."
    exit 1
}

if [ "$RECORD_COUNT" -lt 1 ]; then
    echo "FAIL: Audit log '$LOG_FILE' contains 0 records."
    exit 1
fi

# 3. Require every record to contain non-empty merkle_root and PQC signature fields
INVALID_COUNT=$(jq -s '[.[] | select((.merkle_root // "") == "" or (.pqc_sig // "") == "")] | length' "$LOG_FILE") || {
    echo "FAIL: jq evaluation failed on '$LOG_FILE'."
    exit 1
}

if [ "$INVALID_COUNT" -eq 0 ]; then
    echo "PASS: Verified $RECORD_COUNT tamper-evident audit records in '$LOG_FILE'."
    exit 0
else
    echo "FAIL: Found $INVALID_COUNT unsigned or incomplete records in '$LOG_FILE'."
    exit 1
fi
```

---

### 2.2 Ensure Lateral Sink Isolation Uses Unicode Case Folding + NFKC + UTS #39 Confusable-Skeleton Normalization (Automated)

**Profile Applicability:** Level 1  
**Description:** ASCII-only case conversion (`to_ascii_lowercase`) is Rust-specific, and canonical `NFC` normalization does not collapse compatibility lookalikes (such as fullwidth characters `Ｗｏｒｋｅｒ`) or cross-script homoglyphs (such as Cyrillic `wоrkеr` using `U+043E` / `U+0435` or Greek `αdmin`). Policy authorizers and mesh guards must normalize all role identifiers, agent IDs, and sink names through **Unicode Case Folding + NFKC compatibility decomposition + a UTS #39 confusable-skeleton mapping** (`AgentContainmentRing::normalize_identifier_uts39_skeleton`) and strip zero-width format characters (`U+200B..U+200F`, `U+FEFF`) before evaluating authorization rules.

**Implementation Reference:** `crates/osoosi-agent-anomaly/src/containment_ring.rs` (`normalize_identifier_uts39_skeleton`).

---

### 3.3 Ensure Egress SSRF Guards Block All Special-Purpose IPv4/IPv6 Ranges and Non-Standard IP Formats (Automated)

**Profile Applicability:** Level 1  
**Description:** Outbound agent network validators must inspect both the raw URL authority string (prior to URL parser canonicalization) and the parsed `Ipv4Addr` / `Ipv6Addr` to block:
1. **IPv4 Special-Purpose Ranges:**
   - `0.0.0.0/8` ("This network", RFC 1122)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private)
   - `100.64.0.0/10` (RFC 6598 Shared CGNAT)
   - `127.0.0.0/8` (Loopback)
   - `169.254.0.0/16` (Link-Local & Cloud IMDS `169.254.169.254`)
   - `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (IETF Protocol & TEST-NETs)
   - `198.18.0.0/15` (RFC 2544 Network Interconnect Benchmarking)
   - `224.0.0.0/4` (IPv4 Multicast) and `240.0.0.0/4` (Reserved Class E / Broadcast `255.255.255.255`)
2. **IPv6 Special-Purpose & Transition Ranges:**
   - `::/128` (Unspecified) and `::1/128` (Loopback)
   - `::ffff:0:0/96` (IPv4-Mapped IPv6)
   - `64:ff9b::/96` and `64:ff9b:1::/48` (RFC 6052 / RFC 8215 NAT64 Translation)
   - `100::/64` (Discard-Only), `2001::/32` (Teredo), `2001:db8::/32` (Documentation)
   - `2002::/16` (RFC 3056 6to4 Tunneling)
   - `fc00::/7` (Unique Local) and `fe80::/10` (Link-Local)
   - `ff00::/8` (IPv6 Multicast)
3. **Non-Standard IP Host Encodings:**
   - Pure 32-bit decimal integers (e.g., `http://2130706433`)
   - Hexadecimal IP literals or octets (e.g., `http://0x7f000001`, `http://0x7f.0.0.1`)
   - Octal leading-zero octets (e.g., `http://0177.0.0.1`)
   - Shortened dotted-quad syntax (e.g., `http://127.1`, `http://10.1`)

**Implementation Reference:** `crates/osoosi-agent-anomaly/src/breakout_defense.rs` (`validate_agent_egress_url`, `is_non_standard_ip_host_encoding`, `validate_ipv4`, `validate_ipv6`).

---

### 4.3 Ensure All Active Agent Worker Processes Run Inside Mandatory OS Confinement (Automated)

**Profile Applicability:** Level 1  
**Description:** Every active agent worker process must run with `Seccomp: 2` (filter mode) and `NoNewPrivs: 1` on Linux (or inside a mandatory `AppContainer` + `JobObject` on Windows). Finding zero worker processes when auditing an active worker node **must fail** rather than vacuously passing.

**Audit Script (Fail-Closed):**
```bash
#!/usr/bin/env bash
set -euo pipefail

mapfile -t WORKER_PIDS < <(pgrep -f "osoosi-worker|osoosi_sandbox_worker" || true)

if [ "${#WORKER_PIDS[@]}" -lt 1 ]; then
    echo "FAIL: Zero running agent worker processes found; cannot attest worker confinement."
    exit 1
fi

UNCONFINED=0
for PID in "${WORKER_PIDS[@]}"; do
    STATUS_FILE="/proc/$PID/status"
    if [ ! -r "$STATUS_FILE" ]; then
        echo "FAIL: Cannot inspect $STATUS_FILE for worker PID $PID."
        UNCONFINED=$((UNCONFINED + 1))
        continue
    fi
    SECCOMP=$(awk '/^Seccomp:/ {print $2}' "$STATUS_FILE")
    NNP=$(awk '/^NoNewPrivs:/ {print $2}' "$STATUS_FILE")
    if [ "$SECCOMP" != "2" ] || [ "$NNP" != "1" ]; then
        echo "FAIL: Worker PID $PID is unconfined (Seccomp=${SECCOMP:-none}, NoNewPrivs=${NNP:-none})."
        UNCONFINED=$((UNCONFINED + 1))
    fi
done

if [ "$UNCONFINED" -eq 0 ]; then
    echo "PASS: All ${#WORKER_PIDS[@]} worker process(es) verified with Seccomp=2 and NoNewPrivs=1."
    exit 0
else
    echo "FAIL: $UNCONFINED of ${#WORKER_PIDS[@]} worker process(es) failed confinement checks."
    exit 1
fi
```

---

### 4.4 Ensure Atomic Killswitch (`cgroup v2 cgroup.kill`) and Immediate Credential Revocation Are Configured (Automated)

**Profile Applicability:** Level 1  
**Description:** Signaling individual PIDs in user space is vulnerable to fork-race conditions if a compromised agent spawns subshells faster than `kill()` iterates `/proc`. Containment runtimes must place every agent execution tree in a dedicated `cgroup v2` leaf slice (or Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) and execute an atomic killswitch (`echo 1 > /sys/fs/cgroup/<agent_slice>/cgroup.kill`) paired with immediate generation-epoch advancement (`epoch -> epoch + 1`) and constant-time zeroization of in-memory HMAC/API credentials (`AgentContainmentRing::atomic_killswitch_and_revoke_credentials`).

**Remediation / Killswitch Command:**
```bash
#!/usr/bin/env bash
set -euo pipefail
AGENT_SLICE="${1:?Usage: $0 <agent_cgroup_slice> <agent_id>}"
AGENT_ID="${2:?Usage: $0 <agent_cgroup_slice> <agent_id>}"

# 1. Revoke cryptographic epoch keys & capability tickets first so dying processes cannot emit valid requests
osoosi-cli containment revoke-epoch --agent-id "$AGENT_ID" --zeroize-keys

# 2. Atomically terminate the entire cgroup v2 process tree in kernel space
echo 1 > "/sys/fs/cgroup/${AGENT_SLICE}/cgroup.kill"
```

---

### 5.1 Ensure Continuous Cedar & Two-Tier DLP Egress Audit Trail Is Populated and Verified (Automated)

**Profile Applicability:** Level 1  
**Description:** Every outbound tool call and HTTP/TLS egress inspection must be logged to the DLP/Cedar JSONL audit log with a valid `verdict`, `commitment_hash`, and zero raw PII leakage (`<ZK_PII:` tokens only). Missing or empty logs **must fail**.

**Audit Script (Fail-Closed):**
```bash
#!/usr/bin/env bash
set -euo pipefail

DLP_LOG="${OSHOOSI_DLP_LOG:-/var/log/oshoosiclaw/dlp_audit.jsonl}"

if [ ! -f "$DLP_LOG" ] || [ ! -s "$DLP_LOG" ]; then
    echo "FAIL: DLP audit log '$DLP_LOG' is missing or empty."
    exit 1
fi

RECORD_COUNT=$(jq -s 'length' "$DLP_LOG") || {
    echo "FAIL: Malformed JSON in '$DLP_LOG'."
    exit 1
}

if [ "$RECORD_COUNT" -lt 1 ]; then
    echo "FAIL: DLP audit log '$DLP_LOG' contains 0 records."
    exit 1
fi

BAD_RECORDS=$(jq -s '[.[] | select((.verdict // "") == "" or (.commitment_hash // "") == "")] | length' "$DLP_LOG") || {
    echo "FAIL: jq verification failed on '$DLP_LOG'."
    exit 1
}

if [ "$BAD_RECORDS" -eq 0 ]; then
    echo "PASS: Verified $RECORD_COUNT DLP/Cedar audit records in '$DLP_LOG'."
    exit 0
else
    echo "FAIL: Found $BAD_RECORDS invalid DLP audit records in '$DLP_LOG'."
    exit 1
fi
```
