## Creation of a new Project at Sandbox stage: OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw)

### List of Maintainers
The project has a minimum of one maintainer and is actively expanding its contributor community:
  * Femi Oyesanya, Oshoosi Security, `@oyesanyf` (`https://github.com/oyesanyf`)

### Plan to grow the maintainer and contributor base
  * **Modular Crate Publication**: Publish standalone crates from the 25-crate Rust workspace—including the Dogwood Temporal Policy Engine (`Cedar` + past-only Metric First-Order Temporal Logic) and `osoosi-agent-anomaly` (OWASP Agentic Top 10 `ASI01`–`ASI10` runtime detector & AgentOctopus multi-ring containment)—to `crates.io` so downstream Rust and AI safety teams can adopt and co-maintain individual components.
  * **OpenSSF Working Group Collaboration**: Present technical demonstrations and bi-annual readouts at the **OpenSSF AI/ML Security Working Group** and **OpenSSF Security Tooling Working Group** meetings to onboard co-maintainers from multiple organizations toward Incubating stage requirements (3+ maintainers across 2+ organizations).
  * **Contributor Onboarding & Good First Issues**: Maintain curated `good first issue` and `help wanted` issues across kernel sensors (Windows Minifilter/WFP, Linux eBPF), the 100-table native Rust `siquery` relational SQL engine, and the Agentic Breakout Test Harness, backed by comprehensive architecture and contributor guides (`CONTRIBUTING.md`, `docs/ARCHITECTURE.md`).

### Sponsor
  * **Proposed Sponsoring Working Group**: **OpenSSF AI/ML Security Working Group** or **OpenSSF Security Tooling Working Group** (requesting TAC assistance to assign a Working Group home and WG Sponsor).
  * **Commitment**: The project commits to providing bi-annual updates on technical vision, security baseline compliance, and community growth to the sponsoring Working Group and the TAC.

### GitHub organization
  * **Link to project repository**: https://github.com/oyesanyf/OshoosiClaw
  * **OpenSSF Enterprise Hosting Confirmation**: Confirmed — the repository will be transferred/hosted under the [OpenSSF GitHub Enterprise Cloud instance](https://github.com/enterprises/openssf/organizations) upon Sandbox stage approval.

### Mission of the project
OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw) is an open-source, memory-safe Rust Autonomous Endpoint Detection and Response (EDR) and AI Agent Containment platform. Its mission is to close two critical gaps in the open-source security ecosystem:
1. **Verifiable, Memory-Safe Open-Source EDR**: Provide a transparent, high-assurance Rust endpoint defense platform combining Windows Kernel Minifilter/OB/WFP drivers, Linux eBPF tracepoints, a native Windows Service (`OsoosiEDR`), a 100-table in-process Rust `siquery` relational SQL forensic engine, and a decentralized `libp2p` + Nostr threat intelligence mesh.
2. **Mathematical Containment for Autonomous AI Agents**: Provide runtime detection and multi-ring containment against the **OWASP Top 10 for Agentic Applications (`ASI01`–`ASI10`)**, integrating a `<5µs` statistical screener, `EmbeddingGemma-2` (128-dim Matryoshka) semantic lineage reasoning, zero-hardcode Bayesian agent discovery, GhostJacking/EchoLeak defanging, mathematical IPv4/IPv6 SSRF blocking, Dogwood Temporal Policy (`Cedar` + MFOTL) verification, Distributional Reinforcement Learning (`Dopamine QR-DQN` / `SkyRL`), and exposure-bounded continuum mechanics ($E_{\max} \le B_{\max}$).

### Alignment with the OpenSSF MVSSR
The mission of OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw) directly advances the [OpenSSF Mission, Vision, Values, Strategy, and Roadmap (MVVSR)](https://openssf.org/about/):

* **Strategies**:
  * *i) Catalyst for Change*: Introduces a memory-safe Rust open-source EDR and the first open-source multi-ring containment runtime engineered specifically to prevent autonomous AI coding and OS agents (MCP servers, local LLMs, browser/CLI agents) from escaping workspace boundaries or exfiltrating credentials.
  * *ii) Educate and Empower the Modern Developer*: Empowers developers and security teams with open-source temporal authorization policies (Dogwood Cedar + MFOTL), an interactive 100-table SQL forensic engine, and reproducible adversarial agent breakout benchmarks.
  * *iii) Ecosystem Leader*: Enforces SHA-pinned CI workflows, SLSA v0.2 in-toto provenance attestations, CycloneDX SBOM generation, Authenticode SHA-256 + RFC 3161 signing, and OpenSSF Scorecard supply-chain verification on every build.

* **Pillars**:
  * *i) Programs & Projects*: Delivers a production-ready 25-crate Rust security platform with cross-platform kernel/userspace sensors and signed installer releases.
  * *ii) Education*: Serves as a reference implementation for securing AI agents, formal temporal policy enforcement, and distributional RL defense calibration.
  * *iv) Community & Events*: Facilitates open peer-to-peer threat intelligence sharing (`STIX 2.1` / `TAXII 2.1`) and open-source benchmark evaluation across the security research community.

### IP policy and licensing due diligence
  * **Yes** — All source code in the repository is dual-licensed under `Apache-2.0 OR MIT` (`Cargo.toml` / `LICENSE`), in full compliance with the OpenSSF Charter.

### Project References

| Reference           | URL |
|---------------------|-----|
| Repo                | https://github.com/oyesanyf/OshoosiClaw |
| Latest Release      | https://github.com/oyesanyf/OshoosiClaw/releases/tag/v1.2.0 |
| Contributing guide  | https://github.com/oyesanyf/OshoosiClaw/blob/main/CONTRIBUTING.md |
| Security.md         | https://github.com/oyesanyf/OshoosiClaw/blob/main/SECURITY.md |
| Security Insights   | https://github.com/oyesanyf/OshoosiClaw/blob/main/SECURITY-INSIGHTS.yml |
| Threat Model        | https://github.com/oyesanyf/OshoosiClaw/blob/main/docs/THREAT_MODEL.md |
| Architecture        | https://github.com/oyesanyf/OshoosiClaw/blob/main/docs/ARCHITECTURE.md |
| Operations Manual   | https://github.com/oyesanyf/OshoosiClaw/blob/main/docs/operations_manual.md |
| Code of Conduct     | https://github.com/oyesanyf/OshoosiClaw/blob/main/CODE_OF_CONDUCT.md |
