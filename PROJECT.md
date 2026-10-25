# Project: OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) Stage 2 — Service Profile Fix, Multi-Protocol Rate-Limit Backoff, Confinement Hardening & Full Security Audit

## Architecture
OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) Stage 2 extends the zero-trust EDR & Agent Defense platform across 5 architectural pillars:
1. **Live Browser DLP Windows Service (`SYSTEM`) Profile Discovery & History Deduplication**:
   - Multi-user profile iteration across `C:\Users\*` covering `AppData\Roaming\Microsoft\Windows\Recent`, `AppData\Local\Temp`, `exfil`, `Downloads`, `Desktop`, `Documents`, and `OneDrive` subdirectories.
   - Live browser sink deduplication incorporating file hash and transition window so repeated selections (`A -> B -> A`) on the same browser tab are reliably inspected and contained.
   - Containment engine debounce lifecycle synchronization ensuring un-restored blocks in `st.registry` control suppression and restoring a block clears matching debounce entries.
2. **Multi-Protocol Rate-Limit & Backoff/Jitter Correlation Engine + One-Click UI Rejection**:
   - `crates/osoosi-core/src/rate_limit_backoff.rs` (re-exported in `crates/osoosi-core/src/lib.rs` and synced to `D:\harfile\AgentOctopus\src\security\rate_limit_backoff.rs`).
   - `NetworkProtocol` supporting 11 transport/application protocols (`HttpHttps`, `Tcp` RFC 6298, `Udp`, `Quic` RFC 9002, `Dns`, `Grpc`, `WebSocket`, `Ssh`, `Smtp`, `SmbRdp`, `Icmp`) with 200ms transport / 500ms application RTO floors.
   - `GoogleApiBackoffAnalyzer` calculating truncated exponential backoff ($T_{\text{wait}} = \min(T_{\text{base}} \cdot 2^{\text{attempt}} + \text{rand}(0, 1000\text{ ms}), T_{\text{max}})$) and evaluating `Retry-After` headers with 15% clock skew tolerance.
   - `ReteEngine` with bounded (1024) Alpha memories and Beta join on PID.
   - 3-Voter Ensemble (`DeterministicPhysicsVoter`, `OpenJevDecisionVoter`, `GenerativeLlmVoter`) and Consensus Quorum with 4 Hard Invariants (User Override Allowlist in `database/rate_limit_released_allowlist.json`, Backoff Compliance, Benign Dev Script Immunity, Hostile Containment via `osoosi_core::wfp::block_destination_native`).
   - REST endpoints (`GET /api/har/rate-limit-status`, `POST /api/har/rate-limit-evaluate`, `POST /api/har/rate-limit-release`) and WebUI controls (`🔓 Reject Rate-Limit`, badges, `window.osoosiRateLimit`) with 0-diff parity.
3. **Confined File Truncation, MSVCRT Quoting & Executable Identity Hardening**:
   - `crates/osoosi-sandbox/src/open_confined.rs`: leaf truncation (`set_len(0)`) only after `NumberOfLinks == 1` and canonical path checks succeed; explicit `Result` error handling.
   - `crates/osoosi-sandbox/src/tiered_executor.rs`: Microsoft C/C++ runtime (`CommandLineToArgvW` / MSVCRT) $2n$ / $2n+1$ argument quoting (`quote_windows_argv_arg`, `build_windows_command_line`); AppContainer profile rollback on error and exit paths.
   - `crates/osoosi-sandbox/src/executable_identity.rs`: `%SystemRoot%\System32\` enforcement on `cmd`, `where`, and `curl` (`EXEC_ID_NON_SYSTEM32_SPOOF`); approved installation roots for non-System32 binaries (`EXEC_ID_UNTRUSTED_INSTALL_ROOT`); Unix candidate resolution fallbacks.
4. **Containment Ring, Capability Token, Sticky Taint Floor & SIIT SSRF Hardening**:
   - `crates/osoosi-agent-anomaly/src/containment_ring.rs`: resource boundary single-dot `%2e`, `.%2e`, `%2e.`, `%00`, `%2f`, `%5c`, `%25` rejection; capability token bearer/role/expiry verification before HMAC; severed-arm veto set; sticky `Untrusted` taint floor preserved across >16 relay hops; Cedar reserved principal spoofing block (`CEDAR_PRINCIPAL_SPOOF_BLOCKED`).
   - `crates/osoosi-agent-anomaly/src/mesh_guard.rs`: Untrusted taint floor veto at `PrivilegedSink`.
   - `crates/osoosi-agent-anomaly/src/file_lineage.rs`: scratchpad/temp/tmp immunity negation.
   - `crates/osoosi-agent-anomaly/src/egress_proxy.rs`: RFC 2765 SIIT `::ffff:0:0/96` IPv4-translated IPv6 SSRF blocking.
5. **RAPTOR Pentest, Security Audit, CI Remediation & Release Delivery**:
   - Elimination of `.unwrap()` in `honeytokens.rs:126-127`.
   - Split `curl http://` test fixtures using `concat!(...)`.
   - Upgrade HMAC hashing in `tests/strix_llm_adversarial_tester.py:3549-3561`.
   - Python URL scheme/host validation across test scripts.
   - Remediation of Clippy warnings in `crates/osoosi-dp/src/lib.rs` (lines 793, 1255, 1499) to restore green GitHub Actions CI.
   - RAPTOR analysis & security audit execution.
   - Authenticode signing via native Windows SDK `signtool.exe`, WDSI submission via `scripts/build_and_submit.ps1`, synchronization with `D:\harfile\AgentOctopus`, and shipping via `scripts/solo_pr_ship.ps1`.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Multi-User `Recent\*.lnk` Discovery | Iterate all `C:\Users\*` subdirs for `Recent`, `Temp`, `exfil`, `Downloads`, `Desktop`, `Documents`, and `OneDrive` | M0 | R0, Survey 1 |
| 2 | Live Sink Dedupe Key Integration | Incorporate `compute_live_sink_dedupe_key` into Step 1 history poll key | M0 | R0, Survey 1 |
| 3 | Debounce Clearing & Registry Sync | Clear debounce on restore; require active unrestored block before debouncing in `evaluate_and_respond` | M0 | R0, Survey 1 |
| 4 | `NetworkProtocol` Multi-Protocol Support | 11 protocols (`HttpHttps`, `Tcp`, `Udp`, `Quic`, `Dns`, `Grpc`, `WebSocket`, `Ssh`, `Smtp`, `SmbRdp`, `Icmp`) with RTO floors | M1 | R1, Survey 1 |
| 5 | `GoogleApiBackoffAnalyzer` | Truncated exponential backoff + jitter and 15% clock skew tolerance on `Retry-After` | M1 | R1, Survey 1 |
| 6 | `ReteEngine` & 3-Voter Consensus Quorum | Bounded Alpha/Beta join, 4 Hard Invariants, user allowlist in `rate_limit_released_allowlist.json`, WFP block | M1 | R1, Survey 1 |
| 7 | Rate-Limit REST APIs & WebUI Controls | `GET/POST /api/har/rate-limit-*`, `🔓 Reject Rate-Limit` button, badges, `window.osoosiRateLimit` | M1 | R1, Survey 1 |
| 8 | Confined Leaf File Truncation | Truncate leaf files (`set_len(0)`) only after link count and canonical path checks succeed | M2 | R2, Survey 2 |
| 9 | MSVCRT Command-Line Quoting | Microsoft C/C++ runtime argument quoting rules in `tiered_executor.rs` and Win32 process spawning | M2 | R2, Survey 2 |
| 10 | Executable Identity Hardening | `%SystemRoot%\System32\` check on `curl`/`cmd`/`where`, approved install roots for non-System32, Unix fallbacks | M2 | R2, Survey 2 |
| 11 | AppContainer Profile Rollback | Ensure `rollback_appcontainer_profile` is invoked on all error and exit paths | M2 | R2, Survey 2 |
| 12 | Traversal Percent-Encoding Rejection | Reject single-dot `%2e`, `.%2e`, `%2e.`, `%00`, `%2f`, `%5c`, `%25` at boundary validation gates | M3 | R3, Survey 2 |
| 13 | Capability Token & Severed-Arm Hardening | Verify bearer/role/expiry before HMAC; enforce severed-arm veto set | M3 | R3, Survey 2 |
| 14 | Sticky Taint Floor & Privileged Sink Veto | Preserve earliest `Untrusted` hop across >16 hops; reject `Untrusted` taint floor at `PrivilegedSink` | M3 | R3, Survey 2 |
| 15 | Cedar Principal Spoofing & SIIT SSRF | Block Cedar reserved principal spoofing, scratchpad immunity spoofing, and RFC 2765 SIIT SSRF | M3 | R3, Survey 2 |
| 16 | RAPTOR Static Findings & Test Upgrades | Fix `honeytokens.rs` unwrap, split curl test fixtures, upgrade tester HMAC, Python URL validation | M4 | R4, Survey 3 |
| 17 | CI Clippy Remediation | Fix clippy warnings in `crates/osoosi-dp/src/lib.rs` to fix broken GitHub Actions CI on `main` | M4 | R4, Survey 3 |
| 18 | Cross-Repo Sync (`AgentOctopus`) | Synchronize all rate-limit, boundary, and containment hardening to `D:\harfile\AgentOctopus` | M4 | R4, Survey 3 |
| 19 | Build, WDAC Sign, WDSI & Solo PR Ship | Run `scripts/build_and_submit.ps1` with native SDK `signtool.exe`, WDSI submission, and `scripts/solo_pr_ship.ps1` | M4 | R4, Survey 3 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 0 | M0: Live Browser DLP Service Profile & Debounce Fix | `crates/osoosi-dashboard/src/routes/{har_dlp.rs,dlp_containment.rs}` | none | DONE |
| 1 | M1: Multi-Protocol Rate-Limit Backoff Engine & WebUI | `crates/osoosi-core/src/rate_limit_backoff.rs`, `har.rs`, `dashboard/{src,dist}/views/` | M0 | DONE |
| 2 | M2: Confined Truncation, MSVCRT Quoting & Exec Identity | `crates/osoosi-sandbox/src/{open_confined.rs,tiered_executor.rs,executable_identity.rs}` | none | PLANNED |
| 3 | M3: Containment Ring, Token, Taint Floor & SIIT SSRF | `crates/osoosi-agent-anomaly/src/{containment_ring.rs,mesh_guard.rs,file_lineage.rs,egress_proxy.rs}` | none | PLANNED |
| 4 | M4: RAPTOR Pentest, CI Remediation, WDSI & Solo PR | `crates/osoosi-runtime`, `osoosi-dp`, `scripts/`, `AgentOctopus` sync, `build_and_submit.ps1` | M0, M1, M2, M3 | PLANNED |

## Code Layout
- `crates/osoosi-dashboard/src/routes/har_dlp.rs`: Multi-user profile recent file resolution, live browser history deduplication.
- `crates/osoosi-dashboard/src/routes/dlp_containment.rs`: Containment registry, debounce clearing, and block suppression.
- `crates/osoosi-core/src/rate_limit_backoff.rs`: Multi-protocol rate-limit, exponential backoff, Rete join, voter quorum.
- `crates/osoosi-dashboard/src/routes/har.rs`: Rate-limit status, evaluation, and release endpoints.
- `dashboard/src/views/har.js` & `dashboard/src/views/dlp.js`: WebUI rate-limit badges, reject button, `window.osoosiRateLimit`.
- `crates/osoosi-sandbox/src/open_confined.rs`: Handle-locked leaf truncation and path containment.
- `crates/osoosi-sandbox/src/tiered_executor.rs`: MSVCRT quoting, AppContainer lifecycle rollback.
- `crates/osoosi-sandbox/src/executable_identity.rs`: System32 enforcement, approved install roots, Unix fallbacks.
- `crates/osoosi-agent-anomaly/src/containment_ring.rs`: Boundary traversal encoding rejection, token validation order, severed arms, Cedar spoofing block.
- `crates/osoosi-agent-anomaly/src/mesh_guard.rs`: Untrusted taint floor sink veto.
- `crates/osoosi-agent-anomaly/src/file_lineage.rs`: Scratchpad immunity revocation.
- `crates/osoosi-agent-anomaly/src/egress_proxy.rs`: RFC 2765 SIIT IPv4-translated IPv6 SSRF block.
- `crates/osoosi-dp/src/lib.rs`: Clippy warning fixes (cast losslessness, needless return).
- `scripts/build_and_submit.ps1`: Canonical build, native signtool signing, WDSI submission, GitHub Release sync.
- `scripts/solo_pr_ship.ps1`: Automated post-commit branch creation, PR submission, bot review, and squash-merge.

## Interface Contracts
### `osoosi-core::rate_limit_backoff` ↔ `osoosi-dashboard::routes::har`
- `NetworkProtocol::from_str_or_port(proto: &str, dst_port: Option<u16>) -> Self`
- `GoogleApiBackoffAnalyzer::evaluate_har_stream(entries: &[HarEntrySample]) -> BackoffEvaluationReport`
- `GoogleApiBackoffAnalyzer::evaluate_protocol_stream(proto: NetworkProtocol, samples: &[ProtocolSample]) -> BackoffEvaluationReport`
- `ReteEngine::evaluate_beta_join(&self, pid: u32) -> Option<CorrelatedEvidenceBundle>`
- `RateLimitVoterEnsemble::evaluate_and_vote(&self, bundle: &CorrelatedEvidenceBundle) -> VoterConsensus`

### `osoosi-sandbox::tiered_executor` (MSVCRT Quoting)
- `quote_windows_argv_arg(arg: &str) -> String`: Implements $2n$ / $2n+1$ backslash rules for `CommandLineToArgvW`.
- `build_windows_command_line(prog: &str, args: &[String]) -> String`: Joins executable and arguments using MSVCRT rules.
