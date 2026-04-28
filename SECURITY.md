# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | ✅ Active security patches |
| Tagged releases (`v0.1.x`) | ✅ Critical patches only |
| Older releases | ❌ Not supported |

---

## Reporting a Vulnerability

OshoosiClaw is an autonomous EDR agent. Security bugs — especially agent bypass, false-negative evasion, or privilege escalation via the mesh — are treated as **critical**.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

1. **Email**: Send a detailed report to the maintainer via GitHub's private vulnerability reporting:
   [https://github.com/oyesanyf/OshoosiClaw/security/advisories/new](https://github.com/oyesanyf/OshoosiClaw/security/advisories/new)

2. **Include in your report**:
   - OshoosiClaw version / commit hash
   - Operating system and version
   - Steps to reproduce
   - Proof-of-concept (if available)
   - Potential impact assessment

### Response Timeline

| Stage | Target |
|---|---|
| Acknowledgement | Within 48 hours |
| Severity assessment | Within 5 business days |
| Patch release (Critical) | Within 14 days |
| Patch release (High) | Within 30 days |
| Public disclosure | After patch is released |

---

## Scope

### In-scope (please report)

| Category | Examples |
|---|---|
| **Agent Bypass** | Evading detection of malware by exploiting parser, scoring, or consensus logic |
| **Privilege Escalation** | Abusing the agent's admin/SYSTEM context to escape sandbox or escalate |
| **Mesh Poisoning** | Injecting false consensus votes or corrupting Merkle audit entries |
| **Model Poisoning** | Adversarial inputs that cause the ONNX model to misclassify malware as benign |
| **Dependency Vulnerabilities** | Known CVEs in crates used by OshoosiClaw (`cargo audit` findings) |
| **Secret Exposure** | API keys, mesh node private keys, or certificates committed to the repo |

### Out-of-scope

- Bugs in third-party tools (Sysmon, Hayabusa, Chainsaw) — report to their projects
- UI cosmetic issues in the dashboard
- Performance issues that do not affect security decisions

---

## Security Design Principles

- **No shell execution**: All operations use native Win32/WMI/registry APIs — no `powershell.exe` or `cmd.exe` spawns in production paths
- **Tamper-evident logging**: All security decisions are recorded in a Merkle-chained audit trail (`osoosi merkle`)
- **Byzantine consensus**: Blocking decisions require mesh quorum — no single node can autonomously block without peer agreement
- **Least privilege**: The agent separates host-maintenance (requires admin) from analysis tasks (runs in OpenShell sandbox)
- **Cargo.lock tracked**: Exact dependency versions are pinned and committed — reproducible builds are enforced

---

## Dependency Security

We run `cargo audit` on every pull request via our CI pipeline. If a dependency vulnerability is discovered:

1. We assess whether the vulnerable code path is reachable
2. If reachable: patch is issued within 14 days
3. If not reachable: documented in a GitHub Security Advisory

To check your local build:
```bash
cargo install cargo-audit
cargo audit
```
