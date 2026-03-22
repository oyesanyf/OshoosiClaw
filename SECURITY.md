# Security Policy

## Sovereign Security Model

OpenỌ̀ṣọ́ọ̀sì is built on the principle of **Sovereign Security**. Unlike traditional EDR systems that rely on a centralized cloud for decision-making, OpenỌ̀ṣọ́ọ̀sì agents operate as a decentralized team.

### 1. Authenticated Intelligence (Ed25519)
Every threat signature broadcast across the P2P mesh is cryptographically signed using Ed25519 keys. This prevents "Poisoning Attacks" where a compromised node tries to trick the mesh into blocking legitimate processes.

### 2. Merkle Hash-Chain Audit Trail
Every action taken by the agent (and every critical Sysmon event detected) is recorded in a cryptographically linked Merkle Chain. 
- **Tamper Evidence**: If an attacker gains admin rights and tries to delete local logs, the cryptographic chain breaks, providing evidence of tampering.
- **Forensic Integrity**: Each link in the chain is signed, providing a "Black Box" flight recorder for all security events.

### 3. Taint Tracking
Data exfiltrated or modified is tracked via information flow taint tracking. If a file is downloaded from a suspicious IP (detected via Sysmon), the agent "taints" the file. Any subsequent attempt by a process to execute that tainted file triggers an immediate `Isolate` or `Tarpit` response.

## Reporting a Vulnerability

If you've identified a security vulnerability in OpenỌ̀ṣọ́ọ̀sì, please do not open a public issue. Instead, email security@osoosi.io.

We will:
1. Acknowledge your report within 48 hours.
2. Provide a timeline for a fix.
3. Credit you in our release notes (unless you prefer to remain anonymous).

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |
