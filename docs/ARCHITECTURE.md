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
