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

