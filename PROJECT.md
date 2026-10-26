# Project: OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) — Real-Time DLP Data Lineage & Causal Taint Tracking

## Architecture
OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) implements end-to-end, real-time DLP Data Lineage & Causal Taint Tracking by bridging instrumented AI agents / microservices with uninstrumented native OS processes (`7z.exe`, `tar`, `powershell.exe`, `cmd.exe`, browsers) across 5 architectural pillars:

1. **Synthetic OpenTelemetry Producer & Lock-Free In-Memory Taint State Machine (`DashMap`)**:
   - `crates/osoosi-core/src/dlp_lineage.rs`: High-performance lock-free state machine using `DashMap` with strict lock hygiene (never hold guards across iteration or queries).
   - Collision-immune process keys `(pid: u32, process_start_time: u64)` and path-independent artifact keys `(device_id: u64, inode_or_file_id: u64)`.
   - Out-of-process synthetic `SpanContext` generation (`TraceId`, `SpanId`, `SpanFlags::SAMPLED`), custom kernel timestamps, and W3C `Baggage` (`dlp.classification`, `dlp.source_sha256`, `dlp.policy`, `dlp.tainted`).
   - Strict Lattice Dominance on multi-file merges: Bounded meet-semilattices where strictest classification (`CROWN_JEWEL` > `CONFIDENTIAL` > `INTERNAL` > `PUBLIC`) and policy (`QUARANTINE` > `BLOCK` > `MONITOR`) always win. First tainted file provides the parent `SpanContext`; files 2..N are linked via `Vec<Link>` (`SpanLinks`).
   - Boundary 1 Mitigation: Anti-"Taint Creep" in long-lived processes (`explorer.exe`, IDEs) with active handle descriptor checks (`osquery` `process_open_files`), TTL decay, and content/fuzzy-hash corroboration on benign log writes.
   - Boundary 2 Mitigation: Re-encoding, encryption, or screen-capture transforms (`openssl enc`, `7z.exe`, `.png`) propagating causal taint even with 0% hash/ssdeep similarity.
   - Boundary 3 Mitigation: Out-of-band / cross-host round-trips without headers (new filename & new inode) rehydrated via `SHA-256` and `ssdeep` fuzzy similarity index catalog.

2. **Uninstrumented OS Process/File Correlation via `osquery` (`siquery-rs`) + HAR + Kernel Telemetry**:
   - In-process `siquery-rs` (`crates/osoosi-agent-anomaly/src/siquery.rs`) 103-table engine with live queries on `processes`, `process_open_files`, `process_open_sockets`, `listening_ports`, and `file_events`.
   - Continuous kernel telemetry via Windows ETW (`crates/osoosi-telemetry/src/native.rs`: Process, File, Net, DNS providers) and Linux eBPF (`crates/osoosi-telemetry/src/linux_ebpf.rs`: `bprm_check`, `file_open`, `socket_connect`).
   - Browser sensor & W3C HAR 1.2 traffic inspection (`browser-extension/lib/har-capture.js` and `crates/osoosi-dashboard/src/routes/har_dlp.rs`).
   - Standardized OTel Resource & Span Attributes storing cryptographic digests (`SHA-256`, `ssdeep`) with ZERO raw PII.

3. **Synchronous Inline Egress Blocking & OpenLineage `RunEvent` LogRecord Export**:
   - Nanosecond synchronous inline query on `DashMap` taint table on network egress, HAR upload, or clipboard copy. Immediate block before any byte hits the wire if tainted.
   - Synthetic blocked child span with status `ERROR` and `dlp.action=BLOCKED`.
   - 100% tail-based sampling for tainted traces, anchored into SQLite and Merkle audit trees.
   - Structured OpenLineage `RunEvent` (`InputDataset` -> `Job` -> `OutputDataset`) formatted as JSON and attached to correlated OTel `LogRecord` body.
   - Sub-5ms Axum REST endpoints: `GET /api/dlp/lineage` and `POST /api/dlp/lineage/ingest` in `crates/osoosi-dashboard/src/routes/dlp.rs`.

4. **Clean, Non-Busy Collapsible Data Lineage Section in DLP WebUI (`#dlp`)**:
   - `dashboard/src/index.html` and `dashboard/src/views/dlp.js`, maintaining byte-for-byte `0 diff` parity with `dashboard/dist/`.
   - Collapsed-by-default `<details id="dlp-lineage-details">` with a compact 1-line KPI summary bar.
   - Responsive 3-column expanded view (`InputDataset → Job → OutputDataset/Sink`) with real-time `SpanLinks`, W3C baggage badges, and OpenLineage JSON log preview.

5. **Cross-Repository Synchronization & Documentation**:
   - Architecture updates and Mermaid diagram in `README.md` verified via `python scripts/validate_readme.py`.
   - Synchronization to `D:\harfile\AgentOctopus`.
   - Authenticode signing via native Windows SDK `signtool.exe`, WDSI submission, and zero-wait commits via `scripts/solo_pr_ship.ps1`.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Lock-Free In-Memory Taint State Machine | `(pid, start_time)` and `(device_id, inode_or_id)` `DashMap` state machine with lock hygiene | M1 | R1, Survey 1 |
| 2 | Synthetic OpenTelemetry SpanContext Producer | Construct out-of-process spans (`TraceId`, `SpanId`), parent context, and W3C Baggage | M1 | R1, Survey 1 |
| 3 | Multi-File Merge & Strict Lattice Dominance | First file = parent, files 2..N = `SpanLinks` (`Vec<Link>`), join dominance for classification/policy | M1 | R1, Survey 1 |
| 4 | Boundary 1 Mitigation (Anti-Taint Creep) | Active descriptor check + TTL decay + content/token corroboration on long-lived process log writes | M1 | Addendum, Survey 1 |
| 5 | Boundary 2 Mitigation (Encrypted/Encoded Transforms) | Causal taint propagation across zero-similarity transforms (`openssl`, `7z`, `.png`) | M1 | Addendum, Survey 1 |
| 6 | Boundary 3 Mitigation (Cross-Host Inode Rehydration) | Dual indexing by inode + content digests (SHA-256 + ssdeep) to rehydrate unknown inodes | M1 | Addendum, Survey 1 |
| 7 | `siquery-rs` Open Files & File Events Correlation | Correlate `process_open_files` and `file_events` with taint state machine | M2 | R2, Survey 2 |
| 8 | Kernel Telemetry (ETW / eBPF) Ingestion | Wire ProcessCreate, FileRead, FileWrite, and NetworkConnect events into lineage tracker | M2 | R2, Survey 2 |
| 9 | HAR Web Traffic & Browser DLP Correlation | Correlate multipart uploads, staging files, and URL egress with active taint state | M2 | R2, Survey 2 |
| 10 | Standardized Zero-PII OTel Attributes | Semantic attributes with cryptographic digests (`SHA-256`, `ssdeep`) and zero raw PII | M2 | R2, Survey 2 |
| 11 | Synchronous Nanosecond Inline Egress Blocking | Direct `DashMap` check in egress proxy / network interceptor to block unauthorized sinks | M3 | R3, Survey 2 |
| 12 | Synthetic Blocked Child Span & Tail Sampling | Emit `ERROR` span (`dlp.action=BLOCKED`), retain 100% of tainted traces in SQLite & Merkle tree | M3 | R3, Survey 1 |
| 13 | OpenLineage `RunEvent` to OTel `LogRecord` | Structured JSON payload in `LogRecord.body` correlated with `TraceId` and `SpanId` | M3 | R3, Survey 3 |
| 14 | Sub-5ms Lineage REST Endpoints | `GET /api/dlp/lineage` and `POST /api/dlp/lineage/ingest` in `crates/osoosi-dashboard` | M3 | R3, Survey 3 |
| 15 | Collapsible Data Lineage Section in `#dlp` | Non-busy `<details>` tag with 1-line KPI summary bar and 3-column expanded view | M4 | R4, Survey 3 |
| 16 | WebUI Zero-Diff Parity Enforcement | Byte-for-byte SHA-256 equality between `dashboard/src/` and `dashboard/dist/` | M4 | R4, Survey 3 |
| 17 | README.md Mermaid Architecture Diagram | Comprehensive Mermaid diagram compliant with `scripts/validate_readme.py` | M5 | R5, Survey 3 |
| 18 | Cross-Repo Synchronization to AgentOctopus | Sync containment rings, taint tracking, and lattice dominance to `D:\harfile\AgentOctopus` | M5 | R5, Survey 3 |
| 19 | Full Test Suite & E2E Verification | Pass all unit/integration tests and verify live endpoints on `http://127.0.0.1:3030` | Final | Acceptance Criteria |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Synthetic OTel Producer & Taint State Machine | Features 1–6: `crates/osoosi-core/src/dlp_lineage.rs`, PID/inode keys, lattice dominance, Boundaries 1–3 & unit tests | none | DONE |
| M2 | osquery, HAR & Kernel Telemetry Correlation | Features 7–10: `siquery-rs` `process_open_files`/`file_events`, ETW/eBPF events, HAR correlation, zero-PII attributes | M1 | DONE |
| M3 | Inline Egress Blocking & OpenLineage REST API | Features 11–14: Nanosecond blocking in `egress_proxy`, OpenLineage `RunEvent` log records, sub-5ms REST endpoints | M1, M2 | IN_PROGRESS |
| M4 | Collapsible Data Lineage Section in DLP WebUI | Features 15–16: `<details>` in `dashboard/src/index.html` & `views/dlp.js`, 0-diff parity with `dist/` | M3 | PLANNED |
| M5 | Cross-Repo Sync & Documentation | Features 17–18: `README.md` Mermaid diagram, `AgentOctopus` lockstep sync, `validate_readme.py` | M1–M4 | PLANNED |
| M-Final | Full Test Suite & Automated Release Sync | Feature 19: All cargo tests passing, live HTTP verification, Authenticode signing, WDSI submission, PR ship | M1–M5 | PLANNED |

---

## Interface Contracts

### `DlpLineageTracker` (in `crates/osoosi-core/src/dlp_lineage.rs`)
```rust
pub struct ProcessInstanceKey {
    pub pid: u32,
    pub start_time_100ns: u64,
}

pub struct ArtifactKey {
    pub device_id: u64,
    pub inode_or_file_id: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ClassificationLattice {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    CrownJewel = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PolicyLattice {
    Monitor = 0,
    Block = 1,
    Quarantine = 2,
}

pub struct DlpLineageTracker {
    pub active_processes: DashMap<ProcessInstanceKey, ProcessTaintRecord>,
    pub active_artifacts: DashMap<ArtifactKey, ArtifactTaintRecord>,
    pub content_catalog: DashMap<String, ArtifactTaintRecord>, // keyed by sha256 and ssdeep
    // ...
}
```

### REST API Endpoints (in `crates/osoosi-dashboard/src/routes/dlp.rs`)
- `GET /api/dlp/lineage`: Returns JSON summary of active tainted traces, input datasets, jobs, and output datasets in `< 5ms`.
- `POST /api/dlp/lineage/ingest`: Accepts OpenLineage `RunEvent` or synthetic taint event JSON, updates state machine, and evaluates synchronous policy.

---

## Code Layout
- `crates/osoosi-core/src/dlp_lineage.rs`: Core taint state machine, synthetic OTel producer, lattice dominance, boundary mitigations.
- `crates/osoosi-core/src/lib.rs`: Re-export `dlp_lineage`.
- `crates/osoosi-agent-anomaly/src/siquery.rs`: `file_events` schema and `process_open_files` enrichment.
- `crates/osoosi-dashboard/src/routes/dlp.rs`: `GET /api/dlp/lineage` and `POST /api/dlp/lineage/ingest` routes.
- `dashboard/src/index.html` & `dashboard/dist/index.html`: Collapsed `<details id="dlp-lineage-details">` section.
- `dashboard/src/views/dlp.js` & `dashboard/dist/views/dlp.js`: Lineage rendering and polling logic.
- `README.md`: Architecture diagrams and documentation.
- `D:\harfile\AgentOctopus`: Cross-repository synchronized security controls.
