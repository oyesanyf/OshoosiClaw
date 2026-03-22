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
| `mesh.listen_addrs` | `["/ip4/0.0.0.0/tcp/4001"]` | Multiaddr formats for P2P listening. |
| `mesh.require_attestation` | `true` | If true, peers must pass Mutual Attestation to join. |
| `policy.confidence_threshold` | `0.7` | Threshold at which the agent takes autonomous action. |
| `holograph.enabled` | `true` | Enables distributed deception sharding. |

### Environment Variables
- `OSOOSI_TRUST_SECRET`: Your Ed25519 private key for Node Identity (DID).
- `OSOOSI_DB_PATH`: Path to the SQLite persistence store (default: `osoosi.db`).

---

## 🔬 Scientific Foundations

### The "Speed of Trust"
In a mesh of 1 million nodes, traditional consensus is slow. OpenỌ̀ṣọ́ọ̀sì uses **Gossipsub** for O(1) intelligence propagation. A threat detected in Tokyo is "known" in New York in milliseconds, allowing the New York node to preemptively block the attacker's "Hologram" before a single packet arrives at the local firewall.

### Causal Decoherence
The Einstein Engine uses **BLAKE3 hashing** to link events.
- `Event(t) = Hash(Event(t-1) + Data(t))`
This creates a **State World-Line**. Attackers trying to move laterally or elevate privileges inevitably introduce "foreign data" into the process world-line, causing a hash mismatch (Decoherence).
