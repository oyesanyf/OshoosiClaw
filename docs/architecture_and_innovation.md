# OpenỌ̀ṣọ́ọ̀sì: The Sovereign Mesh Security Agent

OpenỌ̀ṣọ́ọ̀sì (Odídẹrẹ́) is a next-generation, agentic EDR (Endpoint Detection and Response) and self-healing security mesh. It is designed to operate autonomously across Windows, Linux, and macOS, utilizing decentralized intelligence and advanced mathematical models for defense.

---

## 🚀 Key Innovations

### 1. Holographic Deception Sharding (HDS)
Unlike traditional honeypots, HDS creates a **distributed hallucination** across the mesh.
- **Concept**: When an attacker is detected, the mesh generates a "Ghost Persona."
- **Sharding**: The deception is split into "shards" (e.g., Node A simulates SSH, Node B simulates Database, Node C simulates Web).
- **Deterministic Lattice**: Shards are assigned via consensus hashing (`hash(attacker_ip + port)`). An attacker scanning the network perceives a single massive target, while their packets are actually being processed by thousands of different nodes worldwide.

### 2. Einsteinian Relativistic Guard
A temporal security engine that treats system events as a **Causal Manifold**.
- **Light-Cone Integrity**: Every event is hashed with its "causal parent." Any attempt to inject code without a valid causal history (e.g., execution without prior memory allocation) triggers a "Causal Decoherence" alert.
- **Temporal Dilation**: Measures the "Dilation of Truth"—the discrepancy between local system time and global mesh time. This detects "Sleeper Attacks" and clock-skew exploits (TOCTOU) that bypass standard detection.

### 3. CEREBUS-AI CyberShield
A port of the CEREBUS framework providing Explainable AI (XAI) for malware analysis.
- **Explainable Narratives**: Instead of a simple "Malicious" flag, it generates SHAP-inspired narratives explaining *why* a file is suspicious (e.g., "High export size with suspicious imports from kernel32.dll").
- **Resource Interception**: Real-time monitoring of CPU/Memory thresholds to detect cryptojackers and ransomware before they finish encrypting.

### 4. Unified OshoosiClaw Agent (Brain-Payload Merge)
The final evolution of detection precision, merging system discovery utilities with an OpenTelemetry-instrumented Orchestrator.
- **Shannon Entropy Guardrail**: Automatically validates binary intent by analyzing packing and encryption state (Rewards low entropy, alerts high entropy).
- **Forensic Storytelling**: Wraps disconnected system events (Registry, Process, Discovery) into a single, context-rich OTel trace, reducing alert fatigue.
- **NSRL Precision**: Eliminates false positives by cross-referencing KEV matches with the 121GB 'Known Good' database.

---

## 🏗️ System Architecture

- **`osoosi-core`**: The orchestrator. Connects telemetry, policy, and mesh.
- **`osoosi-wire`**: P2P Networking layer using `libp2p` and Gossipsub.
- **`osoosi-policy`**: Sigma-rule engine and KEV/NVD intelligence fetcher.
- **`osoosi-runtime`**: Active response layer (Tarpits, Suspend-Process, Deception).
- **`osoosi-trust`**: Decentralized Identity (DID) and Mutual Attestation.
- **`osoosi-repair`**: Self-healing engine that autonomously discovers and applies security patches.

---

## ⚙️ Setup and Installation

### Prerequisites
- **Rust**: Latest stable toolchain.
- **OS Specifics**:
    - **Windows**: Sysmon installed (provided in root).
    - **Linux**: `auditd` recommended.
    - **macOS**: Endpoint Security permissions.

### Steps
1. **Clone and Build**:
   ```bash
   cargo build --release
   ```
2. **Configure**:
   Copy `osoosi.toml.example` to `osoosi.toml` and adjust your preferences.
   - `OSOOSI_MESH_BOOTSTRAP_PEERS`: List of seed node addresses.
   - `OSOOSI_HDS_ENABLED`: Set to `true` for Holographic Deception.
3. **Run**:
   ```bash
   ./target/release/osoosi-cli start
   ```
4. **Dashboard**:
   Access the local web dashboard at `http://localhost:3000` to monitor threat graphs and mesh health.

---

## 🛡️ Sovereign Security Philosophy
OpenỌ̀ṣọ́ọ̀sì operates on the principle of **Decentralized Sovereignty**. Information about threats is shared at light-speed across the mesh, but every node remains its own "Castle." There is no central server to hack, no single point of failure. The mesh is the security.
