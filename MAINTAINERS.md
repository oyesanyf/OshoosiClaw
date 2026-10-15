# OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw) Maintainers

This file documents the maintainers of the OpenỌ̀ṣọ́ọ̀sì project, following Cloud Native Computing Foundation (CNCF) and Apache Software Foundation (ASF) governance standards.

---

## Core Maintainers

| Name | GitHub Handle | Role | Area of Focus |
| :--- | :--- | :--- | :--- |
| **Folahan Oyesanya** | [@oyesanyf](https://github.com/oyesanyf) | Lead Architect & Project Founder | Core Engine, Kernel Driver, P2P Consensus, Cryptography |

---

## Governance & Decision Making

1. **Consensus-Seeking Architecture**:
   - Architectural proposals, breaking changes, and protocol updates are introduced via RFC pull requests.
   - Core technical decisions require consensus or approval from the project maintainers.

2. **Security & Cryptographic Standards**:
   - Every released executable, library, and MSI installer must be signed with valid Authenticode credentials (`SHA-256` + RFC 3161 timestamp).
   - All external threat intelligence must be validated through consensus voting (Strands Decider, Clef Decision Engine, Byzantine Quorum).
   - Zero-overwrite rule for system and user environment variables (`PATH`) is strictly enforced across all scripts and WiX manifests.

3. **Becoming a Maintainer**:
   - Contributors who demonstrate continuous high-quality contributions, deep architectural understanding, and adherence to security invariants may be nominated as maintainers.
   - Maintainership requires agreement from existing core maintainers.

4. **Emeritus Status**:
   - Maintainers who are inactive for 6 months or more will be transitioned to Emeritus status to maintain active governance hygiene. Emeritus maintainers may be reinstated upon returning to active participation.
