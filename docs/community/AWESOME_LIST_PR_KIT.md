# 🌟 OshoosiClaw Awesome-List Submission Kit

This kit provides ready-to-submit pull request manifests and instructions for integrating **OshoosiClaw** into the top 6 curated GitHub awesome lists in systems programming, security, and AI safety.

---

## 📋 Quick Submission Matrix

| Awesome List | Upstream Repository | Section | Status |
| :--- | :--- | :--- | :---: |
| **awesome-rust** | `rust-unofficial/awesome-rust` | `Applications / Security` | Ready |
| **awesome-ebpf** | `zoidbergwill/awesome-ebpf` | `Security & Observability` | Ready |
| **awesome-security** | `sbilly/awesome-security` | `Endpoint Detection and Response (EDR)` | Ready |
| **awesome-threat-intelligence** | `hslatman/awesome-threat-intelligence` | `Threat Sharing & Peer-to-Peer Feeds` | Ready |
| **awesome-ai-security** | `corca-ai/awesome-ai-security` | `Agent Defense & LLM Containment` | Ready |
| **awesome-incident-response** | `meirwah/awesome-incident-response` | `Host Acquisition and Memory Analysis` | Ready |

---

## 🛠️ Automated Verification Tool

You can validate all PR configurations at any time using the included Python CLI:

```bash
# Run self-test across all 6 manifests
python scripts/prepare_awesome_prs.py --self-test

# Generate formatted PR payload for a specific list
python scripts/prepare_awesome_prs.py --target awesome-rust
```

---

## 1. `rust-unofficial/awesome-rust`

- **Target File**: `README.md`
- **Target Section**: `## Applications / Security`
- **Insertion Entry**:
  ```markdown
  - [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized EDR and autonomous immune system with eBPF CO-RE, YARA-X, NASA F' flight OSAL, and TPM 2.0 PCR 16 attestation.
  ```
- **PR Title**: `Add OshoosiClaw to Applications / Security`
- **PR Description**:
  ```markdown
  ### Summary
  Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) under Applications / Security.

  OshoosiClaw is an open-source, decentralized Endpoint Detection & Response (EDR) platform written in high-assurance Rust (~77%), featuring:
  - eBPF CO-RE Ring-0 probes and Windows ETW/WFP native integration
  - NASA JPL F Prime (`F'`) flight-software backbone with static 16MB zero-alloc arena
  - Autonomous EDR-Bench dual-gate verification harness (`yara-x`)
  - Hardware TPM 2.0 PCR 16 silicon measurements and Ed25519 BFT gossip mesh
  - Zero cloud dependencies, MIT license
  ```

---

## 2. `zoidbergwill/awesome-ebpf`

- **Target File**: `README.md`
- **Target Section**: `## Security & Observability`
- **Insertion Entry**:
  ```markdown
  - [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Autonomous endpoint immune engine using eBPF CO-RE tracepoints for real-time container escape interception and Landlock sandbox fencing.
  ```
- **PR Title**: `Add OshoosiClaw to Security & Observability`
- **PR Description**:
  ```markdown
  ### Summary
  Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) under Security & Observability.

  OshoosiClaw utilizes Linux eBPF CO-RE (Compile Once - Run Everywhere) tracepoints (`sys_enter_bpf`, `sched_process_exec`) combined with Rust to detect unprivileged container escapes in Ring-0 and trigger Landlock nanosecond containment.
  ```

---

## 3. `sbilly/awesome-security`

- **Target File**: `README.md`
- **Target Section**: `## Endpoint Detection and Response (EDR)`
- **Insertion Entry**:
  ```markdown
  - [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized, cloud-free EDR engine featuring Ring-0 kernel drivers, YARA-X synthesis, and automated reverse engineering.
  ```
- **PR Title**: `Add OshoosiClaw to Endpoint Detection and Response`
- **PR Description**:
  ```markdown
  ### Summary
  Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Endpoint Detection and Response (EDR).

  OshoosiClaw provides open-source, local-first endpoint defense without cloud lock-in. Features pre-execution blocking, 101-table live SQL telemetry (`Siquery`), and automated binary reverse engineering (`REA`).
  ```

---

## 4. `hslatman/awesome-threat-intelligence`

- **Target File**: `README.md`
- **Target Section**: `## Threat Sharing & Peer-to-Peer Feeds`
- **Insertion Entry**:
  ```markdown
  - [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized P2P threat mesh sharing STIX 2.1 indicators with ML-KEM-768 post-quantum encryption and TFHE privacy consensus.
  ```
- **PR Title**: `Add OshoosiClaw to Threat Sharing & Peer-to-Peer Feeds`
- **PR Description**:
  ```markdown
  ### Summary
  Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Threat Sharing & Peer-to-Peer Feeds.

  OshoosiClaw implements a decentralized P2P STIX 2.1 gossip network secured by ML-KEM-768 post-quantum key exchange and homomorphic voter consensus, allowing endpoints to share high-fidelity threat indicators without centralized aggregators.
  ```

---

## 5. `corca-ai/awesome-ai-security`

- **Target File**: `README.md`
- **Target Section**: `## Agent Defense & LLM Containment`
- **Insertion Entry**:
  ```markdown
  - [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Fail-closed multi-ring containment for autonomous AI agents, enforcing OWASP Top 10 for Agentic AI, AppContainer, and canary cages.
  ```
- **PR Title**: `Add OshoosiClaw to Agent Defense & LLM Containment`
- **PR Description**:
  ```markdown
  ### Summary
  Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Agent Defense & LLM Containment.

  OshoosiClaw provides pre-execution tool gating, semantic trajectory drift tracking, and AppContainer/Job Object isolation for AI worker agents, defending against prompt injections, SSRF, and credential extraction.
  ```

---

## 6. `meirwah/awesome-incident-response`

- **Target File**: `README.md`
- **Target Section**: `## Host Acquisition and Memory Analysis`
- **Insertion Entry**:
  ```markdown
  - [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Embedded 101-table SQL host telemetry engine (`Siquery`) and autonomous REA binary decompiler for incident response triage.
  ```
- **PR Title**: `Add OshoosiClaw to Host Acquisition and Memory Analysis`
- **PR Description**:
  ```markdown
  ### Summary
  Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Host Acquisition and Memory Analysis.

  OshoosiClaw features `Siquery-RS`, an embedded 101-table virtual SQLite engine for querying volatile host artifacts (processes, sockets, drivers, injected modules) paired with `REA` for autonomous decompiler triage.
  ```
