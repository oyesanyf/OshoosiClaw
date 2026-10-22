# Security Policy

## Supported Versions

OshoosiClaw releases follow Semantic Versioning (`vMAJOR.MINOR.PATCH`). Security updates and critical patches are actively maintained for the following branches and release lines:

| Version Line | Status | Security Patch Support |
| :--- | :---: | :--- |
| `main` branch | Active | Continuous daily patches and vulnerability remediation |
| `v1.2.x` (Current) | Active | Critical vulnerabilities, parser bugs, and mesh security fixes |
| `v1.1.x` | Maintenance | Critical security fixes only |
| `< v1.1.0` | End-of-Life | Unsupported; upgrade to `v1.2.x` immediately |

---

## Reporting a Vulnerability

OshoosiClaw is a critical endpoint detection and response system. Security bugs — particularly agent bypasses, false-negative evasion, privilege escalation, or consensus poisoning — are treated as **critical security emergencies**.

> [!IMPORTANT]
> **Do NOT open public GitHub issues or forum discussions for suspected security vulnerabilities.**  
> Public disclosure exposes production environments before mitigations can be distributed.

### Preferred Reporting Channel: GitHub Security Advisories

Submit reports directly to the maintainers through GitHub's encrypted advisory portal:  
👉 **[Open a Private Security Advisory](https://github.com/oyesanyf/OshoosiClaw/security/advisories/new)**

### Alternative Channel: Encrypted Direct Email

If you cannot access GitHub Advisories, email your disclosure to:  
📧 **[security@oshoosiclaw.dev](mailto:security@oshoosiclaw.dev)** (or maintainer [@oyesanyf](https://github.com/oyesanyf))  
🔑 **PGP Public Key**: Available on GitHub at [https://github.com/oyesanyf.gpg](https://github.com/oyesanyf.gpg)

Please include:
1. **Component / Subsystem**: Affected crate, binary, script, or API endpoint.
2. **Environment & Version**: Operating system (Windows/Linux), OshoosiClaw version / git commit hash.
3. **Vulnerability Type**: Agent bypass, memory corruption, privilege escalation, DLP leak, or consensus spoofing.
4. **Steps to Reproduce & Proof of Concept (PoC)**: Minimal reproduction code, network trace, or test script.
5. **Impact Assessment**: Consequences of exploitation in an enterprise deployment.

---

## Response Timeline & SLA Commitments

The maintenance team commits to the following Service Level Agreements for reported vulnerabilities:

| Incident Stage | Target Window | Action |
| :--- | :---: | :--- |
| **Initial Acknowledgement** | Within **48 hours** | Confirm receipt and establish a private coordination channel. |
| **Triage & Reproducibility** | Within **5 business days** | Validate reproducibility and assign initial CVSS v3.1 / v4.0 severity. |
| **Critical Patch Release** | Within **14 calendar days** | Release hotfix binary, signed MSI, and GitHub Security Advisory. |
| **High Severity Patch** | Within **30 calendar days** | Release patch in the regular release train. |
| **Public Coordinated Disclosure** | Coordinated | Published after users and downstream swarms have patched. |

---

## Vulnerability Scope

### In-Scope Vulnerabilities (Eligible for Coordinated Disclosure)

| Category | Description & Examples |
| :--- | :--- |
| **Agent Bypass & False Negatives** | Novel evasion techniques that bypass Ring-0/ETW sensors, SiQuery telemetry, or decision models without detection. |
| **Privilege Escalation** | Escaping AppContainer / CanaryCage sandbox, Win32 Job Object confinement, or Linux namespace barriers. |
| **Mesh & Consensus Poisoning** | Forging `ML-DSA-65` signatures, byzantine peer equivocation, or corrupting Merkle audit ledgers. |
| **Data Loss Prevention (DLP) Exfiltration** | Techniques that evade RedactX-v3 OpenJEV hybrid logit scoring, secret unwrappers, or crown-jewel Merkle chunks. |
| **AI Agentic Exploitation (ASI01–ASI10)** | Indirect prompt injections escaping agent boundary, unauthorized tool invocation, or memory trajectory hijacking. |
| **Cryptographic Flaws** | Broken lattice implementations in ML-KEM-768 / ML-DSA-65, TFHE ciphertext leakage, or weak RNG seeds. |
| **Supply Chain & Dependencies** | Exploitable CVEs in workspace crates identified via `cargo audit`. |

### Out-of-Scope

- Attacks requiring physical device theft with unencrypted bitlocker and compromised physical TPM.
- Cosmetic styling issues in the WebUI that do not impact security state.
- Bugs in upstream, third-party standalone tools (e.g. Sysmon, Hayabusa) without an OshoosiClaw integration vulnerability.
- Denial of Service attacks originating from an attacker who already possesses root/SYSTEM privileges on the target host.

---

## Security Architecture & Invariant Principles

- **Zero Shell Hot-Paths**: Telemetry, inspection, and enforcement paths execute exclusively via native Win32/ETW/eBPF APIs without spawning external shells (`cmd.exe`, `powershell.exe`, `/bin/sh`).
- **Multi-Voter Consensus**: High-impact containment (`Isolate`, `Tarpit`) requires multi-voter consensus (`detector_count >= 2`, confidence $\ge 0.90$) and respects human-in-the-loop gates.
- **Fail-Closed Isolation**: Boundary violations in AppContainer profiles or Job Objects immediately fail closed and terminate child handles.
- **Air-Gapped by Default**: External WAN relays (Nostr/DuckDNS) and remote LLMs are strictly opt-in; all threat analysis operates fully local.
- **Signed Authenticode & SLSA Attestations**: All Windows executables, libraries, and MSI packages are Authenticode signed with native `signtool.exe` (SHA-256 + RFC 3161 timestamp) and verified via SLSA v1.0 DSSE attestations.
- **Automated WDSI Submission**: All release artifacts are submitted to Microsoft Security Intelligence.

---

## Security Hall of Fame & Acknowledgments

We believe in recognizing security researchers who responsibly report vulnerabilities. Contributors will be credited in our GitHub Security Advisories, release notes, and our public security acknowledgments page (unless anonymity is requested).
