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

### 6. AI Agent Security & Policy Voters (Cloudflare Audit Integration)
Incorporating the Cloudflare Security Audit Framework, the EDR's multi-modal consensus engine incorporates real-time host telemetry voters:
- **`AiSecurityAuditVoter`**: Evaluates live host execution events for AI-specific attacks:
  - **Tool-Argument Injection**: Inspects command-line arguments passed to agent tools for command chaining (`;`, `&&`, `|`), encoded scripts (`powershell -enc`), and path traversals (`../`, `..\`) into sensitive system files.
  - **State & Memory Poisoning**: Intercepts Sysmon Event 11 writes targeting agent memory stores (`.agents/memory.md`), policy rules (`.agents/rules/`), and configuration files (`osoosi.toml`).
  - **Process Memory Safety**: Detects external processes attempting remote thread creation (Event 8) or memory modification (`PROCESS_VM_WRITE`) into AI runtimes.
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
