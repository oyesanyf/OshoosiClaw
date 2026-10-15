# System Operations & Technical Deep Dive

## 🔍 How the System Works

OpenỌ̀ṣọ́ọ̀sì follows a **Sense-Think-Act** loop tailored for decentralized security.

### 1. The Sensing Layer (Telemetry)
- **Multi-Source Ingestion**: The agent watches `sysmon` (Windows), `auditd` (Linux), and `ESF` (macOS).
- **Normalization**: Diverse logs are normalized into `HostSecurityEvent` structures.
- **Audit Chain**: Every ingested event is logged into a local **Tamper-Evident Merkle Logchain**. This ensures that even if an attacker gains root, they cannot erase their footprints without breaking the cryptographic root hash.

### 2. The Thinking Layer (Intelligence)
- **Policy Engine**: Evaluates Sigma rules against normalized events.
- **Threat Intelligence**: Periodically fetches KEV (Known Exploited Vulnerabilities) and NVD data to update its risk scoring.
- **Relativistic Guard**: Applies the Einsteinian logic to verify the causal history of process events.
- **CEREBUS-AI**: Runs binary feature extraction on suspicious files to provide XAI narratives.

### 3. The Acting Layer (Response)
- **Local Response**: Tarpitting (suspending processes), firewall blocking, and file quarantining.
- **Mesh Consensus**: If a local node fixes a vulnerability (using `osoosi-repair`), it broadcasts a **Policy Health Vote**. If the mesh reaches consensus, other nodes automatically adopt the fix.
- **Holographic Lattice**: Active redirection of attacker traffic into virtual deception shards.

---

## 🛠️ Detailed Configuration

The system is controlled via the `osoosi.toml` file and Environment Variables.

### Key Configuration Parameters

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `mesh.listen_addrs` | `["/ip4/0.0.0.0/tcp/9000"]` | Multiaddr formats for P2P listening. |
| `mesh.require_attestation` | `true` | If true, peers must pass Mutual Attestation to join. |
| `policy.confidence_threshold` | `0.7` | Threshold at which the agent takes autonomous action. |
| `holograph.enabled` | `true` | Enables distributed deception sharding. |

### Environment Variables
- `OSOOSI_TRUST_SECRET`: Your Ed25519 private key for Node Identity (DID).
- `OSOOSI_DB_PATH`: Path to the SQLite persistence store (default: `osoosi.db`).
- `OTX_API_KEY` / `NVD_API_KEY`: Threat feed API keys (see `[external_api]` in `osoosi.toml`).
- `OPENSHELL_CLI_PATH`: Full path to the NVIDIA **OpenShell** CLI when not on `PATH` (required for `osoosi start --sandbox` handoff).
- `OSOOSI_GIT_PATH`: Full path to `git` / `git.exe` when using `osoosi sandbox install` with VCS URLs (`git+https://…`).

### External tools cache (OpenShell / Git)

On every `osoosi start`, the agent **resolves** the `openshell` and `git` executables by searching `PATH`, `%ProgramFiles%\Git\cmd\git.exe` (via environment), Python `Scripts` layouts, and related heuristics — **without hard-coded drive letters** for portable installs. Successful paths are saved to:

- **Windows:** `%APPDATA%\osoosi\tool_paths.json`
- **Unix:** `$XDG_CONFIG_HOME/osoosi/tool_paths.json` or `~/.config/osoosi/tool_paths.json`

The next run reads this file first (after explicit `OPENSHELL_CLI_PATH` / `OSOOSI_GIT_PATH`). Use `osoosi sandbox install` to bootstrap OpenShell via pip, `git+https://github.com/NVIDIA/OpenShell.git`, or `uv tool install`.

---

## 🔬 Scientific Foundations

### The "Speed of Trust"
In a mesh of 1 million nodes, traditional consensus is slow. OpenỌ̀ṣọ́ọ̀sì uses **Gossipsub** for O(1) intelligence propagation. A threat detected in Tokyo is "known" in New York in milliseconds, allowing the New York node to preemptively block the attacker's "Hologram" before a single packet arrives at the local firewall.

### Causal Decoherence
The Einstein Engine uses **BLAKE3 hashing** to link events.
- `Event(t) = Hash(Event(t-1) + Data(t))`
This creates a **State World-Line**. Attackers trying to move laterally or elevate privileges inevitably introduce "foreign data" into the process world-line, causing a hash mismatch (Decoherence).

## 🏗️ Resilience & Hardening (v1.1+)

OshoosiClaw includes several "Production Hardening" features to ensure stability in hostile or unstable environments:

### 1. Resilient Threat Feeds
- **Exponential Backoff**: OTX and NVD fetchers now use jittered exponential backoff (2s, 4s, 8s) to survive transient network failures.
- **Fail-Safe Cache**: If a feed cannot be reached after 3 retries, the agent falls back to the last successful local cache to ensure continuous protection.

### 2. Hardened Repair Engine
- **Transactional Rollbacks**: The Windows Repair Engine uses isolated PowerShell script blocks for `Checkpoint-Computer`, preventing parameter binding errors.
- **Graceful DISM Cleanup**: Rollback failures are caught and logged as warnings rather than fatal errors, preventing agent crashes during failed system uninstalls.

### 3. Asynchronous AI Provisioning
- **Lazy Loading**: `MalConv` weights (`malconv.safetensors`) are downloaded in the background on startup. The agent remains functional in a "Degraded AI" state until weights are hot-loaded into the ML pipeline.

### 4. Log Debouncing
- **Spam Protection**: Behavioral alerts are debounced at the orchestrator level. Unique alerts (by reason) are throttled to once every 5 minutes to prevent dashboard/log inundation during high-frequency activity.

### 5. AI Voter #24 Troubleshooting (Behavioral AI Cortex)
If you see "PRODUCTION-CRITICAL: All ML models failed to load":
- **Gemma Shards**: If `decoder_model_merged.onnx_data` is missing but `_1`, `_2` shards exist, the agent will attempt automatic concatenation on next start. Ensure you have at least 8GB of free disk space.
- **SecureBERT**: Ensure `models/securebert/model.onnx` exists. If missing, run `osoosi provision`.
- **Defender Error 225**: If the agent logs "Operation did not complete successfully because the file contains a virus", Windows Defender is blocking the AI from reading the forensic scripts.
  - **Fix**: Run `Add-MpPreference -ExclusionPath "C:\TEST"` (or your test directory) in an Admin PowerShell.

### 6. Mesh Handshaking & Firewalls
- **Port Requirements**: Oshoosi Mesh requires **TCP/UDP 9000-9010** and **TCP 4001** to be open for sibling discovery.
- **Connection Timeout (10061)**: Indicates the peer is unreachable. Verify that `mesh.listen_addrs` in `osoosi.toml` is set to `0.0.0.0` and that your hardware firewall allows P2P traffic.

### 7. Autonomous Defense Swarm Operation (`tools/defense_swarm/`)
- **FastAPI Microservice (Port 4002)**: The LangGraph multi-agent defense swarm runs on `127.0.0.1:4002`.
- **Start Swarm Service**:
  ```powershell
  python -m defense_swarm.cli serve --host 127.0.0.1 --port 4002
  # Or via Windows batch launcher:
  .\tools\defense_swarm\bin\defense-swarm.cmd serve
  ```
- **Operator Review Gate (`/api/approvals`)**: High-risk remediation actions pause at the `human_review_node` using LangGraph `interrupt()`. Operators review the synthesized incident narrative and click **Approve** or **Reject** in the WebUI.
- **CLI Verification**:
  ```powershell
  .\osoosi.exe swarm status
  .\osoosi.exe swarm test --pid 5555 --engine clef --confidence 0.95
  ```

### 8. Multi-Tiered Hybrid Decision Engine Operations
- **Strands Decider 2B + Clef Flash**: Combines Cloudflare Workers AI edge models with AWS Strands Decider 2B (open-source local SLM).
- **Routing Strategies**:
  - `cascade`: Fastest evaluation, falling back from Clef to Strands Decider 2B.
  - `consensus`: Dual-query ensemble averaging probabilities for zero false-positive containment.
  - `local_first`: 100% on-device inference for air-gapped data sovereignty.
- **CLI Diagnostics**:
  ```powershell
  .\osoosi.exe decision status
  .\osoosi.exe decision test
  .\osoosi.exe decision evaluate --state "Process: Mimikatz.exe | CmdLine: sekurlsa::logonpasswords | MITRE: T1003"
  ```

### 9. Embedded Velociraptor Forensics Operations
- **Deep Process & Disk DFIR**:
  ```powershell
  # Check forensics service status
  .\osoosi.exe forensics status
  # Inspect VAD allocations for unbacked executable (RWX) code injection
  .\osoosi.exe forensics inspect-process --pid 1844
  # Scan raw NTFS MFT for rootkit file hiding and timestomping
  .\osoosi.exe forensics scan-mft --drive C --dir "Windows\Temp"
  ```

### 10. Windows Service Administration (OsoosiEDR)
OpenỌ̀ṣọ́ọ̀sì can run continuously as a native Windows Service (`OsoosiEDR`) managed by the Windows Service Control Manager (SCM). The service automatically starts on system boot, auto-recovers after unhandled crashes, resolves the repository/install root dynamically from `current_exe()`, and serves the interactive WebUI on **`http://127.0.0.1:3030/`** via a dedicated 4-worker Tokio runtime (`osoosi-dashboard-rt`).

#### SCM Service Management Operations
If invoked from a standard (non-Admin) terminal, `osoosi service <action>` automatically requests Windows UAC elevation (`Start-Process -Verb RunAs`), or falls back to spawning a WMI-detached background daemon (`Win32_Process.Create`) if UAC is unavailable—automatically waiting for `http://127.0.0.1:3030/` to become ready and opening the browser in your interactive desktop session:

| Operational Goal | OpenỌ̀ṣọ́ọ̀sì CLI | Native PowerShell | Native Win32 `sc.exe` |
| :--- | :--- | :--- | :--- |
| **Install Service** | `.\osoosi.exe service install` | *N/A* | `sc.exe create OsoosiEDR binPath= "..." start= auto` |
| **Start Service** | `.\osoosi.exe service start` | `Start-Service OsoosiEDR` | `sc.exe start OsoosiEDR` |
| **Check Status** | `.\osoosi.exe service status` | `Get-Service OsoosiEDR` | `sc.exe queryex OsoosiEDR` |
| **Stop Service** | `.\osoosi.exe service stop` | `Stop-Service OsoosiEDR` | `sc.exe stop OsoosiEDR` |
| **Restart Service** | `.\osoosi.exe service restart` | `Restart-Service OsoosiEDR` | `sc.exe stop OsoosiEDR && sc.exe start OsoosiEDR` |
| **Delete / Remove** | `.\osoosi.exe service delete` | *N/A* | `sc.exe delete OsoosiEDR` |

#### Operational Modes: Monitor Mode vs. Enforce Mode
When conducting penetration tests, adversary simulations (`edr_tester.py`), Atomic Red Team drills, or research swarms (`rfc_hunt_swarm.py`), operators must be aware of the daemon's active operational mode:

- **Monitor Mode (`Action: Logged and Alerted`)**:
  - Configured via `policy.enforce = false` or `autonomy_mode = "audit"` in `osoosi.toml`.
  - In Monitor Mode, the EDR observes and processes all kernel telemetry, runs EMBER ML feature extraction, and evaluates multi-voter consensus without killing processes or dropping connections.
  - **Verification Method**: Check daemon logs for `Consensus Threat Identified`, query the SQLite database (`database/osoosi.db`) for entries in the `threats` and `consensus_findings` tables, and verify threat broadcast messages across the P2P wire mesh (`GossipSub`) and Nostr relays.
  - *Working-Directory Caution*: When querying the database while the service is running, always verify the active daemon CWD (`Get-CimInstance Win32_Process -Filter "Name = 'osoosi.exe'"`), as `database/osoosi.db` resolves relative to the process directory (e.g. `target/release/database/osoosi.db` in release builds).
- **Enforce Mode (`Blocked / Quarantined / Process Terminated`)**:
  - Configured via `policy.enforce = true` or `autonomy_mode = "active"` in `osoosi.toml`.
  - In Enforce Mode, verified threats above the confidence threshold ($> 0.80$) immediately trigger active mitigation: process thread freezing (`ActiveProcessTarpit`), Windows Filtering Platform (WFP) network socket isolation, file quarantine, and process tree termination (`Kill Process Tree`).

### 11. Host-Calibrated Model Provisioning (osoosi pull-model)
To maximize detection and reasoning performance without exceeding host hardware limits, OpenỌ̀ṣọ́ọ̀sì features an automated hardware diagnostic and model provisioning pipeline:

#### 1. Hardware Inspection (`osoosi check-resources`)
Run hardware diagnostics to inspect host logical cores, physical RAM, free memory, and GPU VRAM:
```powershell
.\osoosi.exe check-resources
# Aliases: .\osoosi.exe doctor, .\osoosi.exe resources
```
This categorizes the machine into one of four hardware tiers:
- **UltraLite (<4 GB RAM)**: Magika + EMBER v2 static models only; browser UI suppressed.
- **Lite (4-8 GB RAM)**: SOREL-20M, SecureBERT, and Cloudflare Clef Flash; browser suppressed unless forced.
- **Standard (8-16 GB RAM)**: Strands Decider 2B and LangGraph Swarm; web browser enabled.
- **Enterprise (>16 GB RAM)**: Full reasoning models (Qwen 2.5 14B/32B, FoundationSec-8B, EmbeddingGemma 2).

#### 2. Model Pull Pipeline (`osoosi pull-model`)
Automatically download and configure the model suite recommended for the host tier:
```powershell
# Automatically detect tier and pull all calibrated models
.\osoosi.exe pull-model

# Or pull a specific calibrated model directly
.\osoosi.exe pull-model qwen2.5:14b
```
Operators can also trigger model downloads with one click from the interactive WebUI under the **Utilities** tab (`#utilities-view`).

#### 3. Automatic IPv6 Restoration Guard (`Ipv6SuspensionGuard`)
Multi-gigabyte downloads from Hugging Face or Cloudflare R2 frequently stall on dual-stack Windows network adapters due to silent IPv6 routing timeouts and broken PMTU discovery:
- `Ipv6SuspensionGuard` automatically identifies active network adapters and temporarily unbinds IPv6 (`Disable-NetAdapterBinding -ComponentID ms_tcpip6`) during the download session.
- Transfers seamlessly utilize reliable IPv4 TCP connections at line rate.
- An RAII Drop guard guarantees that IPv6 bindings (`Enable-NetAdapterBinding`) are automatically restored once the transfer finishes, errors out, or is cancelled.

### 12. Native Rust `siquery-rs` SQL Engine & CLI Operations (`osoosi siquery`)

OpenỌ̀ṣọ́ọ̀sì includes an integrated, zero-dependency in-process SQL engine providing 100% table and feature parity with Devolutions' `siquery-rs`. It enables security operators and autonomous decision models to query all 41 operating system tables through standard ANSI SQL queries without requiring external binaries (`osqueryi.exe`).

#### CLI Execution Patterns

```powershell
# 1. List all 41 available system tables
.\osoosi.exe siquery --list

# 2. Inspect the column schema and types for a specific table
.\osoosi.exe siquery --schema process_memory_map
.\osoosi.exe siquery --schema wmi_services

# 3. Query all records from a table in JSON format
.\osoosi.exe siquery --all system_info --json

# 4. Dump entire table in pipe-delimited CSV format
.\osoosi.exe siquery --all etc_hosts --csv

# 5. Execute relational SQL joins in Pretty ASCII table mode
.\osoosi.exe siquery --pretty -q "SELECT p.pid, p.name, s.remote_address, s.remote_port, s.state FROM processes p JOIN process_open_sockets s ON p.pid = s.pid WHERE s.state = 'LISTEN' LIMIT 15;"

# 6. Check unbacked executable memory regions (in-memory injection & hollowing detection)
.\osoosi.exe siquery --json -q "SELECT pid, base_address, region_size, state, protect, mapped_file FROM process_memory_map WHERE protect LIKE '%EXECUTE%' LIMIT 20;"

# 7. Audit auto-start Windows services
.\osoosi.exe siquery --pretty -q "SELECT name, display_name, start_mode, state, path_name FROM wmi_services WHERE start_mode = 'Auto' LIMIT 20;"
```

#### Interactive WebUI Console (`#siquery-view`)

Operators can navigate to the **Siquery SQL Console** in the WebUI (`http://127.0.0.1:3030/#siquery`):
- **41-Table Dictionary**: Filterable list of all 41 operating system tables with one-click query generation (`SELECT * FROM <table> LIMIT 15;`).
- **One-Click Security Presets**: Quick buttons for Top Processes, Listening Sockets, WMI Services, Network Adapters, Windows Hotfixes, User Accounts, Hosts File MITM, and Memory Maps.
- **Output Formats**: Live interactive JSON tables with column sorting, raw ASCII monospace terminal output, or pipe-delimited CSV with single-click clipboard copy and file export.
- **Live EDR Telemetry Summary**: Real-time counters showing active monitored processes, open network sockets, WMI services, shares, and EDR sweep status.

#### REST API Endpoints

| Endpoint | Method | Description |
|:---|:---|:---|
| `/api/siquery/tables` | `GET` | Returns an array of all 41 registered system tables and total count. |
| `/api/siquery/query` | `POST` | Executes SQL queries (`query`, `format: json\|pretty\|csv`) and returns rows with `execution_duration_ms`. |
| `/api/siquery/edr-status` | `GET` | Returns cached or freshly swept 6-dimension EDR security telemetry. |
| `/api/agent-anomalies/containment-status` | `GET` | Returns active 4-Ring agent containment states, isolated sessions, and breakout counts. |

---

## 📈 Performance & Resource Tuning
- **Adaptive Mode**: The agent dynamically scales its analysis depth based on CPU load. If CPU > 80%, the AI Cortex will skip non-critical event sentences.
- **Concurrency Limits**: Adjust `adaptive.max_concurrency` in `osoosi.toml` to limit the number of parallel model inferences.

