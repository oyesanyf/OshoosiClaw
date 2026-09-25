# OshoosiClaw Architecture

> Deep technical documentation of the OshoosiClaw EDR architecture.

---

## Overview

OshoosiClaw follows a **modular monolith** pattern — 20 specialized Rust crates compiled into a single binary. This gives us the deployment simplicity of a monolith with the code organization benefits of microservices.

## Core Data Flow

```
                    ┌─────────────────────────┐
                    │   Sysmon Kernel Driver   │ ← Pre-existing, signed by Microsoft
                    │   (ETW Event Producer)   │
                    └───────────┬─────────────┘
                                │ All 25+ Event IDs
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│                    osoosi-telemetry                                │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Host Event       │  │ File Watcher │  │ Provisioner          │ │
│  │ Reader (ETW)     │  │ (FIM + Hash) │  │ (Sysmon/ClamAV/etc) │ │
│  └────────┬────────┘  └──────┬───────┘  └──────────────────────┘ │
└───────────┼──────────────────┼───────────────────────────────────┘
            │                  │
            ▼                  ▼
┌───────────────────────────────────────────────────────────────────┐
│                    osoosi-core (EdrOrchestrator)                   │
│                                                                   │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────────┐  │
│  │ NSRL     │    │ Policy   │    │ Threat   │    │ Behavioral │  │
│  │ Fast-Path│───▶│ Engine   │───▶│ Model    │───▶│ Classifier │  │
│  │ (3-tier) │    │ (Sigma)  │    │ (EMBER)  │    │ (AI)       │  │
│  └──────────┘    └──────────┘    └──────────┘    └────────────┘  │
│       │               │              │                │           │
│       ▼               ▼              ▼                ▼           │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │     CAPA → FLOSS → HollowsHunter → Hayabusa → Chainsaw     │   │
│  │              (Deep Forensic Analysis Pipeline)              │   │
│  └────────────────────────────────────────────────────────────┘   │
│       │                                                           │
│       ▼                                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Audit Trail  │  │ Mesh         │  │ Active Response      │   │
│  │ (Merkle Log) │  │ (Broadcast)  │  │ (Quarantine/Tarpit)  │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

## Detection Tiers

OshoosiClaw uses a **tiered detection model** to balance speed and depth:

### Tier 0: NSRL Fast-Path (Sub-millisecond)
Before any analysis, every process hash is checked against the **NIST NSRL** (National Software Reference Library) — a 121 GB database of known-good software hashes.

- **L1**: In-memory DashMap cache (nanoseconds)
- **L2**: SQLite persistent cache with integrity flag (microseconds)
- **L3**: Authoritative NSRL database lookup (milliseconds)

If the hash is "Known Good," the event is **immediately skipped** — zero false positive.

### Tier 1: Policy Engine (Milliseconds)
Sigma rule matching + NVD/KEV intelligence correlation.

### Tier 2: ML Threat Model & Shannon Guardrails (Milliseconds)
- **EMBER-style 54-feature PE static analysis** + **MalConv Deep Byte Analysis** with local ONNX Runtime inference.
- **Shannon Entropy Analysis**: A primary guardrail for precision. 
  - **Low Entropy (< 6.5)**: Rewards legitimate browsers/tools with a risk-score reduction.
  - **High Entropy (> 7.5)**: Boosts confidence for packed/encrypted malware.
- **Precision KEV Matching**: Dynamic CISA KEV matching cross-referenced with NSRL to eliminate false positives for patched legitimate software.
- **ClamAV Consensus Voter**: Provides formal "clean" or "infected" votes to the consensus engine. "Clean" results act as positive reinforcement with a negative weight, while "Infected" results provide high-confidence alerts.

### Tier 2.5: OpenTelemetry Forensic Storytelling
Suspicious behaviors (Registry access, discovery) are wrapped in **OpenTelemetry-instrumented spans**. This turns isolated alerts into a single, context-rich "Forensic Story," reducing alert volume by up to 80% while maintaining a full audit trail.

### Tier 3: Behavioral AI (Seconds)
CoLog → SecureBERT → Gemma 3 → OpenAI cascade.

### Tier 4: CAPA + FLOSS (Seconds)
Deep capability extraction and string de-obfuscation for unknown files.

### Tier 5: HollowsHunter Memory Forensics (Seconds)
Triggered **reactively** by Sysmon events:
- **Event ID 10 (ProcessAccess)** targeting `lsass.exe` → credential dumping
- **Event ID 8 (CreateRemoteThread)** → code injection

### Tier 6: C2 Detection (Real-time & Forensic)
Specialized engines for spotting Command & Control activity:
- **Hayabusa**: Host-based Sigma rule engine for Event Log analysis.
- **Chainsaw**: Fast triage of MFT and system artifacts.
- **RedBPF**: Real-time Linux kernel monitoring for network beacons.
- **Xori**: Shellcode emulation for pre-execution capability detection.
- **yara-x**: Native Rust pattern matching for malware families.

### 4. Privacy Layer (Cryptographic Hardening)
The Privacy Layer enforces **Differential Privacy (DP)** and **Merkle-Chain Integrity** on all mesh-wide communications.
- **Merkle Proofs**: All threat intelligence is cryptographically attested to a node's local audit trail.
- **Differential Privacy**: Laplacian noise is injected into threat scores to prevent adversary fingerprinting of node behavior.
- **Homomorphic Encryption**: Enables secure, decentralized aggregation of threat metrics without revealing raw telemetry.

### 5. Military Guard (Tactical Defense)
The Military Guard provides advanced detection for asymmetric warfare patterns typically used by nation-state actors.
- **Phantom-Mesh Detection**: Identifies unauthorized P2P "whispering" for lateral movement.
- **Sleeper-Strike (Loitering) Monitor**: Detects dormant processes that execute sudden "Alpha Strikes" after long periods of inactivity.
- **Anti-Chaff Filter**: Neutralizes decoy traffic intended to blind the EDR's monitoring capabilities.

### 6. AI Agent Security & Policy Voters (MITRE ATLAS™ & Cloudflare Audit Integration)
Incorporating both the official **MITRE ATLAS™** (Adversarial Threat Landscape for Artificial-Intelligence Systems) taxonomy and Cloudflare's Security Audit Framework, the EDR's multi-modal consensus engine includes real-time host telemetry voters:
- **`AiSecurityAuditVoter`**: Evaluates live host execution events for AI-specific attacks, mapping directly to canonical MITRE ATLAS technique IDs:
  - **Tool-Argument Injection (`AML.T0043`)**: Inspects command-line arguments passed to agent tools for command chaining (`;`, `&&`, `|`), encoded scripts (`powershell -enc`), and dangerous subshell executions -> `ResponseAction::Tarpit`.
  - **Insecure Output & Path Traversal (`AML.T0044`)**: Detects path traversals (`../`, `..\`) through LLM-directed tools targeting sensitive files (`/etc/passwd`, `System32`, `.env`, `.aws`, `id_rsa`) -> `ResponseAction::Tarpit`.
  - **Agent Memory & State Poisoning (`AML.T0048` / `AML.T0018`)**: Intercepts Sysmon Event 11 writes targeting persistent agent memory stores (`.agents/memory.md`), policy rules (`.agents/rules/`), and configuration files (`osoosi.toml`) -> `ResponseAction::Isolate`.
  - **Execution Environment Tampering (`AML.T0040`)**: Detects external non-AI processes attempting remote thread creation (`CreateRemoteThread`, Event 8) into AI runtimes (`python.exe`, `ollama.exe`) -> `ResponseAction::Isolate`.
  - **Disarm AI Safeguards & Memory Tampering (`AML.T0029`)**: Detects external processes requesting memory modification access (`PROCESS_VM_WRITE | PROCESS_VM_OPERATION`, Event 10) into AI agent runtimes -> `ResponseAction::Isolate`.
- **`AgenticVoter`**: Evaluates generative and agentic runtime vectors:
  - **LLM Jailbreaks & Obfuscated Injections (`AML.T0051`)**: Detects Base64-encoded, caret-escaped (`p^w^r^s^h^e^l^l`), and polymorphic jailbreak prompts attempting safety bypass -> `ResponseAction::Tarpit`.
  - **Training Data / System Prompt Exfiltration (`AML.T0054`)**: Alerts on unauthorized exfiltration of system prompt directives, proprietary RAG context, or credentials -> `ResponseAction::Alert`.
  - **Denial of ML Service (`AML.T0042`)**: Detects algorithmic sponge attacks, recursive tool loops, and token exhaustion -> `ResponseAction::Tarpit`.
- **`ZeroDayVoter`**: Detects model serialization backdoors and poisoned checkpoints (`AML.T0031`) -> `ResponseAction::Isolate`.
- **Consensus Deduplication Cache Hardening**: Caches multi-voter verdicts using a multi-attribute tuple Blake3 hash: $\text{Blake3}(\text{BinaryHash} \parallel \text{ProcessName} \parallel \text{ReasonCategory} \parallel \text{CommandLine} \parallel \text{TargetFilename})$, guaranteeing zero cross-command verdict collisions while sustaining sub-millisecond evaluation.
- **`AgenticPolicyVoter`**: Dynamic minimax defense, goal alignment evaluation, and agentic escape detection.
- **`AgentEgressVoter`**: Threat-observed outbound network egress control, DNS covert channel detection, and adaptive traffic throttling.

### 7. CyberShield Developer Tool & Local AI Protection
CyberShield provides real-time resource anomaly monitoring and process mitigation with hardened developer protections:
- **Local AI Engine Whitelist**: AI inference engines (`llama-server`, `ollama`, `vllm`, `tritonserver`, `tabby`) are recognized as developer tools and protected from false-positive active response suspensions.
- **C2 Kill Guard**: Developer tools will never be terminated or suspended on heuristic resource anomalies unless verified by a confirmed C2 beacon signature ($\text{score} \ge 0.95$).
- **YARA C2 Precision**: Built-in C2 detection (`C2_Beacon_Generic`) strictly matches authentic BishopFox Sliver protobuf/RPC signatures (`sliverpb.SliverRPC`, `sliver.pb.go`), eliminating false positives on English word matches.
- **Kernel Subsystem Bypass**: System kernel processes (PID 0, PID 4, `System`, `Registry`) are exempted from user-space resource kill actions.
- **Runtime False-Positive Exclusions**: Git MinGW binaries (`\Program Files\Git\mingw64\`), Google Drive sync temp directories (`\.tmp.driveupload\`), and Hugging Face caches are whitelisted in `scanner_skip_path` and `is_ide_or_build_path`.

### 8. Resilient Model & Threat Feed Provisioning
- **NSRL RDS Streaming**: Features dynamic directory writability probes, buffered async writes (8MB `BufWriter`), automatic fallback to alternate cache locations, and clean task cancellation handling.
- **Cross-Crate Provisioning State**: Atomic state tracking via `osoosi_types::is_model_provisioning()` coordinates download states across crates, ensuring smooth fallback to Ollama or heuristic classifiers without transient startup error log spam.

### 9. Resilient P2P Mesh Discovery & Socket Guardrails
- **Multi-Adapter Local IP Enumeration**: `RouteScraper::get_local_ip_addresses()` uses native Windows IP Helper APIs (`GetIpAddrTable`) and UDP routing lookups to dynamically identify all local adapter IPv4 addresses across physical, virtual (WSL2, Hyper-V), and VPN interfaces.
- **Strict Self-Dial Prevention**: Prevents node loopback collisions and Windows Winsock error 10048 (`WSAEADDRINUSE`) by blacklisting all machine-assigned IPs from subnet discovery dials.
- **Pre-Flight TCP Discovery Probing**: Before initiating a cryptographic libp2p Swarm connection attempt against ARP-discovered subnet hosts, a lightweight non-blocking TCP probe (80ms timeout) checks if port 4001 is actively listening. Disconnected or non-Oshoosi devices (printers, IoT) are skipped immediately, preventing kernel socket exhaustion and Swarm connection state churn.
- **Adaptive Socket Exhaustion Backoff**: Swarm connection errors track consecutive `WSAEADDRINUSE` occurrences; only persistent exhaustion ($\ge 3$ consecutive collisions) triggers aggressive discovery backoff and system-wide telemetry throttling, while transient collisions (< 3) are logged at `debug` level.
- **Bidirectional Peer Identity Handshake**: Every node broadcasts `agent_version: "osoosi/0.1.1"` and matches peers across `agent_version`, `protocol_version`, and supported protocols (`/osoosi/1.0.0`). Discovered peers are immediately added to Gossipsub (`add_explicit_peer`), auto-approved, and dialed via mDNS to eliminate disconnect loops.
- **Kademlia Bootstrap Protection**: Periodic DHT bootstrap triggers are gated on active peer connectivity (`self.swarm.connected_peers().count() > 0`), suppressing unseeded `Failed to trigger bootstrap: No known peers` warnings.
- **Extended Idle Connection Keep-Alive**: Swarm idle connection timeout is extended to 300s, ensuring stable P2P telemetry channels during heavy model download or background inference tasks.

### 10. P2P Wire Mesh STIX 2.1 Synchronization (`osoosi-wire`)
- **Authoritative STIX 2.1 Bundle**: 26,381 objects uniting MITRE ATT&CK Enterprise (v19.2) and MITRE ATLAS (v2026.09), correlated with 4,334 production Sigma rules.
- **GossipSub Channel (`osoosi-stix-sync-v1`)**: Peer-to-peer distribution of cryptographic `StixManifest` with Blake3 checksum and verified object count.
- **Zero-Downtime Hot-Reloading**: In-memory catalog replacement without daemon restart or telemetry interruption.
- **Dual-Target Parity**: Strict synchronization across development (`dashboard/src/`) and production (`dashboard/dist/`) directories.



## Response Matrix

| Confidence | Action | Description |
|:-----------|:-------|:------------|
| < 0.4 | None | Below detection threshold |
| 0.4 - 0.6 | Alert | Log + Dashboard notification |
| 0.6 - 0.8 | GhostTarpit | Deploy decoys + throttle connections |
| 0.8 - 0.95 | Isolate | Network isolation + mesh broadcast |
| > 0.95 | Quarantine | File quarantine + process termination |

## Trust Model

```
Agent A                          Agent B
   │                                │
   │  1. DID Challenge              │
   │ ──────────────────────────────▶│
   │                                │
   │  2. Signed Attestation         │
   │ ◀──────────────────────────────│
   │  (Binary hash + Memory state)  │
   │                                │
   │  3. Verify + Issue S2S Cert    │
   │ ──────────────────────────────▶│
   │                                │
   │  4. Mutual mTLS Established    │
   │ ◀────────────────────────────▶ │
   │  (Gossipsub over secure channel)│
```

Every agent has a `did:osoosi:` Decentralized Identifier backed by an Ed25519 key pair. Trust is **earned** through consistent, accurate threat reporting and **mathematically verified** through Merkle proofs.
