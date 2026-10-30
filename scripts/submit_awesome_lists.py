#!/usr/bin/env python3
"""
OshoosiClaw — 4-Vertical Awesome Lists Traction & Automated PR Submission Engine
================================================================================
Automates inspection, tailored entry generation, README section patching, fork management,
and Pull Request creation across 20 curated Awesome Lists spanning four distinct verticals:

  Vertical 1: Direct EDR & Detection Engineering
    - shadawck/awesome-endpoint-detection-and-response
    - infosecB/awesome-detection-engineering
    - 0x4D31/awesome-threat-detection
    - threat-hunting/awesome_Threat-Hunting

  Vertical 2: Broad Blue Team, DFIR, Forensics & Reverse Engineering
    - fabacab/awesome-cybersecurity-blueteam
    - A-poc/BlueTeam-Tools
    - sbilly/awesome-security
    - meirwah/awesome-incident-response
    - cugu/awesome-forensics
    - dsopas/awesome-reverse-engineering

  Vertical 3: Rust & eBPF Systems Directories
    - rust-unofficial/awesome-rust
    - osirislab/awesome-rust-security
    - 0xflotus/awesome-rust-security
    - qmonnet/awesome-ebpf
    - zoidbergwill/awesome-ebpf
    - aya-rs/awesome-aya

  Vertical 4: Specialized Signature (YARA) & Agentic AI Security Lists
    - InQuest/awesome-yara
    - pedramamini/awesome-yara
    - corca-ai/awesome-ai-security
    - requie/awesome-ai-cybersecurity

Usage:
  python scripts/submit_awesome_lists.py --list
  python scripts/submit_awesome_lists.py --generate-bundle
  python scripts/submit_awesome_lists.py --verify-remote
  python scripts/submit_awesome_lists.py --submit --vertical 1 --dry-run
  python scripts/submit_awesome_lists.py --submit --repo shadawck/awesome-endpoint-detection-and-response --execute
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CANONICAL_REPO_URL = "https://github.com/oyesanyf/OshoosiClaw"
CANONICAL_RELEASE_URL = "https://github.com/oyesanyf/OshoosiClaw/releases/latest"


@dataclass
class AwesomeListTarget:
    repo: str
    vertical: int
    vertical_name: str
    wave: int
    category_focus: str
    target_sections: List[str]
    entry_markdown: str
    pr_title: str
    pr_body: str
    readme_candidates: List[str] = field(
        default_factory=lambda: ["README.md", "readme.md", "Readme.md"]
    )


AWESOME_LIST_TARGETS: List[AwesomeListTarget] = [
    # =========================================================================
    # VERTICAL 1: Direct EDR & Detection Engineering (Wave 1)
    # =========================================================================
    AwesomeListTarget(
        repo="shadawck/awesome-endpoint-detection-and-response",
        vertical=1,
        vertical_name="Direct EDR & Detection Engineering",
        wave=1,
        category_focus="Endpoint Agents & Active Response Engines",
        target_sections=["EDR", "Agents", "Endpoint Detection and Response", "Open Source EDR", "Tools"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Cross-platform Rust and eBPF/ETW "
            "Endpoint Detection & Response (EDR) agent with multi-voter Bayesian behavioral consensus, "
            "YARA-X memory/file scanning, 7-Ring Cedar capability containment, and active process/network quarantine."
        ),
        pr_title="Add OshoosiClaw (Rust + eBPF/ETW Endpoint Detection & Active Response Engine)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the EDR / Endpoint Agents list.\n\n"
            "### Why OshoosiClaw Fits\n"
            "- **Native Rust + eBPF / Windows ETW & Minifilter Telemetry**: Zero-overhead kernel and user-space sensor mesh for Linux, Windows, and macOS.\n"
            "- **Active Response & Containment**: Process termination, AppContainer / seccomp-bpf + Landlock sandboxing, Ransomware canary rollback, and automated quarantine.\n"
            "- **Multi-Voter Behavioral Consensus**: Combines YARA-X, Clef Decision Engine, MITRE ATT&CK behavioral correlation, and Universal Binary/Bytecode inspection.\n"
            "- **Signed Releases**: Available via MSI, DEB, RPM, macOS Universal tarballs, and hardened distroless containers (`https://github.com/oyesanyf/OshoosiClaw/releases/latest`)."
        ),
    ),
    AwesomeListTarget(
        repo="infosecB/awesome-detection-engineering",
        vertical=1,
        vertical_name="Direct EDR & Detection Engineering",
        wave=1,
        category_focus="Telemetry Collection, YARA/Sigma Rule Synthesis & Agentic Triage",
        target_sections=["Logging, Monitoring & Data Sources", "Detection Content & Signatures", "Tools", "Endpoint"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Rust detection engineering and EDR "
            "platform combining kernel telemetry (eBPF/ETW), automated YARA-X signature synthesis, "
            "CI/CD workflow supply-chain guards, and multi-agent Bayesian alert triage."
        ),
        pr_title="Add OshoosiClaw to Detection Engineering Tools",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the Detection Engineering collection.\n\n"
            "### Key Detection Engineering Capabilities\n"
            "- **Telemetry + Detection Pipeline**: Streams eBPF (Linux), ETW/Minifilter (Windows), and EndpointSecurity (macOS) telemetry through a deterministic MITRE ATT&CK behavioral engine.\n"
            "- **Automated YARA-X Rule Synthesis & Verification**: Extracts grounded indicators and synthesizes validated YARA-X and Cedar policies with false-positive calibration.\n"
            "- **Agentic Alert Triage & Reproducible Live Probing**: Continuously tests detection rules against live breakout and attack payloads with full SQLite & OpenLineage audit provenance.\n\n## Affiliation\n- [x] I am the author, maintainer, or otherwise affiliated with this project."
        ),
    ),
    AwesomeListTarget(
        repo="0x4D31/awesome-threat-detection",
        vertical=1,
        vertical_name="Direct EDR & Detection Engineering",
        wave=1,
        category_focus="Host Monitoring Stacks & Threat Detection",
        target_sections=["Endpoint", "Tools", "Host-based", "Detection", "EDR"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - High-performance Rust host threat "
            "detection and active response engine featuring eBPF/ETW kernel probes, YARA-X scanning, "
            "process hollowing detection, and cryptographic Merkle audit logging."
        ),
        pr_title="Add OshoosiClaw (Rust Host Threat Detection & EDR Engine)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** under host-based threat detection tools.\n\n"
            "### Highlights\n"
            "- Cross-platform host monitoring stack written in Rust (`osoosi`).\n"
            "- Detects credential dumping, process hollowing, reflective DLL/SO injection, LOTL abuse, and container escapes.\n"
            "- Built-in YARA-X engine, eBPF/ETW sensors, and Nostr/libp2p decentralized threat intelligence sharing."
        ),
    ),
    AwesomeListTarget(
        repo="threat-hunting/awesome_Threat-Hunting",
        vertical=1,
        vertical_name="Direct EDR & Detection Engineering",
        wave=1,
        category_focus="Threat Hunting & Endpoint Telemetry",
        target_sections=["Tools", "Hunting Tools", "Endpoint", "Host"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Autonomous threat hunting and EDR "
            "agent in Rust with osquery/HAR data lineage, eBPF/ETW kernel telemetry, Universal Reverse Engineering "
            "(PE/ELF/Mach-O/WASM/EVM), and live MITRE ATT&CK hunting workflows."
        ),
        pr_title="Add OshoosiClaw to Threat Hunting Tools",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the Threat Hunting tools section.\n\n"
            "### Threat Hunting Features\n"
            "- Real-time process lineage, memory anomaly hunting, and network beacon / JA3 / DNS entropy analysis.\n"
            "- Integrated osquery + HAR + OpenLineage data exfiltration hunting.\n"
            "- Built-in Universal Binary & Bytecode reverse engineering and YARA-X rule generation."
        ),
    ),

    # =========================================================================
    # VERTICAL 2: Broad Blue Team, DFIR, Forensics & Reverse Engineering (Wave 2)
    # =========================================================================
    AwesomeListTarget(
        repo="fabacab/awesome-cybersecurity-blueteam",
        vertical=2,
        vertical_name="Broad Blue Team, DFIR, Forensics & Reverse Engineering",
        wave=2,
        category_focus="Endpoint Detection and Response, Host-Based Tools & Threat Hunting",
        target_sections=[
            "Endpoint Detection and Response",
            "Host-Based Tools",
            "Threat Hunting",
            "Incident Response",
        ],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Production Rust EDR, Host IPS, and "
            "7-Ring AI agent containment platform with eBPF/ETW kernel sensors, YARA-X memory scanning, "
            "ransomware canary protection, and Universal Binary/Bytecode inspection."
        ),
        pr_title="Add OshoosiClaw to Endpoint Detection and Response",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the **Endpoint Detection and Response** section.\n\n"
            "### Overview for Blue Teams\n"
            "- **Full-Stack Open-Source EDR/IPS**: Written in Rust for Windows (ETW, AMSI, Minifilter, AppContainer), Linux (eBPF, seccomp-bpf, Landlock v3), and macOS.\n"
            "- **Ransomware & Credential Defense**: Entropy-aware canary decoys, LSASS/SAM access blocking, and automated binary quarantine.\n"
            "- **Zero-Trust Supply Chain & CI/CD Guard**: Built-in GitHub Actions workflow vulnerability scanner, Witness DSSE attestations, and OPA Rego verification."
        ),
    ),
    AwesomeListTarget(
        repo="A-poc/BlueTeam-Tools",
        vertical=2,
        vertical_name="Broad Blue Team, DFIR, Forensics & Reverse Engineering",
        wave=2,
        category_focus="Blue Team Defense & Active Response",
        target_sections=["EDR", "Endpoint", "Host", "Defensive Tools", "Tools"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Cross-platform Rust Blue Team EDR "
            "and active defense daemon providing eBPF/ETW kernel monitoring, YARA-X scanning, DLP enforcement, "
            "and automated incident containment."
        ),
        pr_title="Add OshoosiClaw (Rust Blue Team EDR & Active Defense Suite)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to BlueTeam-Tools.\n\n"
            "### Capabilities\n"
            "- Real-time endpoint detection and active containment across Windows, Linux, and macOS.\n"
            "- Memory forensics, YARA-X scanning, browser/network DLP, and CIS Benchmark compliance auditing."
        ),
    ),
    AwesomeListTarget(
        repo="sbilly/awesome-security",
        vertical=2,
        vertical_name="Broad Blue Team, DFIR, Forensics & Reverse Engineering",
        wave=2,
        category_focus="General Security & Endpoint Defense",
        target_sections=["Anti-Virus / Anti-Malware", "Endpoint", "Monitoring", "System"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Rust-based Endpoint Detection & "
            "Response (EDR), Host IPS, and kernel telemetry framework using eBPF, Windows ETW, and YARA-X."
        ),
        pr_title="Add OshoosiClaw to Security Monitoring / Endpoint Tools",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-security`.\n\n"
            "### Description\n"
            "OshoosiClaw is an open-source, memory-safe Rust EDR and active defense platform combining kernel-level telemetry (eBPF/ETW), YARA-X signature scanning, and formal Cedar policy enforcement."
        ),
    ),
    AwesomeListTarget(
        repo="meirwah/awesome-incident-response",
        vertical=2,
        vertical_name="Broad Blue Team, DFIR, Forensics & Reverse Engineering",
        wave=2,
        category_focus="Incident Response, Containment & Memory Forensics",
        target_sections=["All-in-one", "Endpoint", "Memory Analysis", "Collection", "Tools"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Cross-platform incident response and "
            "EDR agent in Rust with live process containment, RWX/unbacked memory forensics, automated "
            "quarantine rollback, and cryptographic Merkle evidence trails."
        ),
        pr_title="Add OshoosiClaw to Incident Response Tools",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-incident-response`.\n\n"
            "### Incident Response Capabilities\n"
            "- **Immediate Host Containment**: Process tree suspension/termination, network isolation, and quarantine with one-click restoration.\n"
            "- **Live Memory & Binary Forensics**: Detects RWX shellcode regions, unbacked thread execution, PE/ELF header stomping, and generates forensic YARA-X rules."
        ),
    ),
    AwesomeListTarget(
        repo="cugu/awesome-forensics",
        vertical=2,
        vertical_name="Broad Blue Team, DFIR, Forensics & Reverse Engineering",
        wave=2,
        category_focus="Deep Binary, Memory & Artifact Forensics",
        target_sections=["Live Forensics", "Frameworks", "Tools"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Rust forensic inspection and EDR suite "
            "supporting PE/ELF/Mach-O/WASM/EVM/.NET/APK/SQLite/HAR/PCAP artifact analysis, live memory "
            "anomaly detection, and tamper-evident Merkle audit chains."
        ),
        pr_title="Add OshoosiClaw to Forensics Tools / Frameworks",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-forensics`.\n\n"
            "### Forensic Features\n"
            "- **Multi-Format Artifact Inspector**: Native Rust analysis of PE, ELF, Mach-O, Rust `cargo-auditable`, Go `BuildInfo`, WASM, EVM bytecode, .NET CIL, Android APK/DEX, Electron ASAR, SQLite WAL/freelist pages, and HAR/PCAP captures.\n"
            "- **Tamper-Evident Evidence Ledger**: Ed25519 + ML-DSA-65 post-quantum signed Merkle audit logs."
        ),
    ),
    AwesomeListTarget(
        repo="wtsxDev/reverse-engineering",
        vertical=2,
        vertical_name="Broad Blue Team, DFIR, Forensics & Reverse Engineering",
        wave=2,
        category_focus="Universal Binary & Bytecode Reverse Engineering (REA)",
        target_sections=["Binary Analysis", "Bytecode Analysis", "Disassemblers"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Autonomous Reverse Engineer Anything "
            "(REA) engine in Rust for inspecting PE/ELF/Mach-O binaries, Rust `cargo-auditable` & Go `BuildInfo` "
            "symbols, WASM, EVM bytecode, .NET CIL, Android APKs, and Electron ASAR archives with automated YARA-X signature generation."
        ),
        pr_title="Add OshoosiClaw (Universal Binary & Bytecode Reverse Engineering Engine)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-reverse-engineering`.\n\n"
            "### Reverse Engineering Capabilities\n"
            "- **Universal Binary & Bytecode Inspection (`osoosi-rea`)**: Parses and reconstructs control flow, imports/exports, entropy anomalies, and embedded manifests across PE, ELF, Mach-O, WASM, EVM bytecode, .NET CIL, Android APK/DEX, and Electron ASAR.\n"
            "- **Toolchain Metadata Recovery**: Extracts Rust `cargo-auditable` dependency graphs and Go `BuildInfo` symbol tables from stripped binaries.\n"
            "- **Automated YARA-X Synthesis**: Generates deterministic YARA-X signatures directly from extracted binary artifacts."
        ),
    ),

    # =========================================================================
    # VERTICAL 3: Rust & eBPF Systems Directories (Wave 3)
    # =========================================================================
    AwesomeListTarget(
        repo="rust-unofficial/awesome-rust",
        vertical=3,
        vertical_name="Rust & eBPF Systems Directories",
        wave=3,
        category_focus="Rust Security & Systems Monitoring",
        target_sections=["Security", "System tools"],
        entry_markdown=(
            "* [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Cross-platform Endpoint Detection & "
            "Response (EDR), Host IPS, and AI agent containment platform powered by Rust, eBPF, Windows ETW, "
            "YARA-X, and Cedar policy verification. ([repo](https://github.com/oyesanyf/OshoosiClaw))"
        ),
        pr_title="Add OshoosiClaw to Security section",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the **Security** section of `awesome-rust`.\n\n"
            "### Crate & Architecture Highlights\n"
            "- 100% workspace-modularized Rust security platform (`osoosi`, `osoosi-core`, `osoosi-ebpf`, `osoosi-sandbox`, `osoosi-agent-anomaly`, `osoosi-dashboard`).\n"
            "- Integrates `yara-x`, `cedar-policy`, `wasmtime`, `rusqlite`, and native eBPF / Win32 AppContainer isolation."
        ),
    ),
    AwesomeListTarget(
        repo="tylerha97/awesome-reversing",
        vertical=3,
        vertical_name="Rust & eBPF Systems Directories",
        wave=3,
        category_focus="Rust Security Tools & Defensive Engines",
        target_sections=["Binary Analysis", "Bytecode Analysis", "Disassemblers/Decompilers"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Memory-safe Rust EDR, Host IPS, "
            "Universal Binary Inspector, and 7-Ring capability sandbox with eBPF/ETW kernel telemetry and YARA-X."
        ),
        pr_title="Add OshoosiClaw (Rust EDR, Host IPS & Binary Analysis Platform)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-rust-security`.\n\n"
            "### Why It Belongs\n"
            "Demonstrates production defensive systems engineering in Rust: kernel telemetry (eBPF/ETW), `yara-x` scanning, `wasmtime` + Win32 AppContainer / Linux Landlock sandboxing, and post-quantum (ML-DSA-65) Merkle audit logging."
        ),
    ),
    AwesomeListTarget(
        repo="0xflotus/awesome-rust-security",
        vertical=3,
        vertical_name="Rust & eBPF Systems Directories",
        wave=3,
        category_focus="Rust Security & Defensive Infrastructure",
        target_sections=["Tools", "Security", "Network", "System", "Forensics"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Cross-platform Rust Endpoint Detection "
            "& Response (EDR) and zero-trust capability sandbox with eBPF/ETW probes and YARA-X."
        ),
        pr_title="Add OshoosiClaw to Rust Security Tools",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `0xflotus/awesome-rust-security`."
        ),
    ),
    AwesomeListTarget(
        repo="qmonnet/awesome-ebpf",
        vertical=3,
        vertical_name="Rust & eBPF Systems Directories",
        wave=3,
        category_focus="eBPF in Security",
        target_sections=["Security", "eBPF in Security", "Monitoring", "Tracing"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Rust-based Endpoint Detection & "
            "Response (EDR) and container breakout prevention engine using eBPF tracepoints, LSM hooks, and "
            "seccomp-bpf for real-time syscall anomaly detection and privilege escalation blocking."
        ),
        pr_title="Add OshoosiClaw to Security section",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the **Security** section of `awesome-ebpf`.\n\n"
            "### eBPF Implementation Details\n"
            "- Uses eBPF (`crates/osoosi-ebpf`) to monitor `execve`, `ptrace`, `memfd_create`, `bpf`, `mount`, `setns`, `unshare`, and socket connect events in real time.\n"
            "- Combines eBPF ring-buffer telemetry with seccomp-bpf syscall filtering and Landlock v3 filesystem confinement to prevent container and AI agent breakouts."
        ),
    ),
    AwesomeListTarget(
        repo="zoidbergwill/awesome-ebpf",
        vertical=3,
        vertical_name="Rust & eBPF Systems Directories",
        wave=3,
        category_focus="eBPF Kernel Probe Instrumentation & Security",
        target_sections=["Security", "Tools", "Tracing", "Monitoring"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Rust + eBPF security monitoring and "
            "active response agent detecting fileless `memfd_create` execution, `setns`/`unshare` namespace "
            "escapes, and unauthorized network egress."
        ),
        pr_title="Add OshoosiClaw (Rust + eBPF Security Monitoring & EDR Agent)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the Security section of `awesome-ebpf`."
        ),
    ),
    AwesomeListTarget(
        repo="aya-rs/awesome-aya",
        vertical=3,
        vertical_name="Rust & eBPF Systems Directories",
        wave=3,
        category_focus="Rust-based eBPF Security Monitoring Agents",
        target_sections=["Projects", "Security", "Tools", "Applications"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Pure-Rust Endpoint Detection & "
            "Response (EDR) and runtime security daemon leveraging Rust eBPF kernel probes (`osoosi-ebpf`) "
            "for syscall telemetry, container escape detection, and active process containment."
        ),
        pr_title="Add OshoosiClaw (Rust eBPF Endpoint Detection & Security Monitoring Agent)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-aya`.\n\n"
            "### Overview\n"
            "OshoosiClaw's Linux kernel sensor crate (`crates/osoosi-ebpf`) integrates Rust eBPF kernel probes with user-space async Tokio telemetry pipelines, YARA-X scanning, and Cedar policy enforcement."
        ),
    ),

    # =========================================================================
    # VERTICAL 4: Specialized Signature (YARA) & Agentic AI Security Lists (Wave 4)
    # =========================================================================
    AwesomeListTarget(
        repo="InQuest/awesome-yara",
        vertical=4,
        vertical_name="Specialized Signature (YARA) & Agentic AI Security Lists",
        wave=4,
        category_focus="YARA Tools, Scanners & Automated Rule Generation",
        target_sections=["Tools", "Scanners", "Generators", "Services"],
        entry_markdown=(
            "* [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Rust EDR and Universal Binary Inspector "
            "integrating native `yara-x` memory/file scanning with automated YARA rule synthesis from reverse-engineered "
            "PE/ELF/Mach-O/WASM/APK artifacts and over 1,600 curated multi-OS detection rules."
        ),
        pr_title="Add OshoosiClaw to Tools (YARA-X Scanner & Automated Rule Synthesizer)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the **Tools** section of `awesome-yara`.\n\n"
            "### YARA Capabilities\n"
            "- **Native `yara-x` Engine**: High-speed Rust YARA-X scanning across live process memory and filesystem streams.\n"
            "- **Automated YARA Rule Generator**: Synthesizes and validates YARA rules directly from binary analysis (PE/ELF/Mach-O/WASM/EVM/APK) and arXiv security research extraction.\n"
            "- **1,600+ Production Rules**: Ships with a verified corpus of Windows, Linux, macOS, and ransomware YARA signatures."
        ),
    ),
    AwesomeListTarget(
        repo="pedramamini/awesome-yara",
        vertical=4,
        vertical_name="Specialized Signature (YARA) & Agentic AI Security Lists",
        wave=4,
        category_focus="YARA Tools, Scanners & Rule Generators",
        target_sections=["Tools", "Scanners", "Generators"],
        entry_markdown=(
            "* [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Rust EDR and Universal Binary Inspector "
            "featuring native `yara-x` live memory/file scanning, automated YARA rule synthesis, and 1,600+ "
            "multi-platform detection signatures."
        ),
        pr_title="Add OshoosiClaw to YARA Tools",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the **Tools** section of `awesome-yara`."
        ),
    ),
    AwesomeListTarget(
        repo="corca-ai/awesome-llm-security",
        vertical=4,
        vertical_name="Specialized Signature (YARA) & Agentic AI Security Lists",
        wave=4,
        category_focus="Agentic AI Security, 7-Ring Cedar Containment & Breakout Prevention",
        target_sections=["Tools", "Defense", "Platform Security"],
        entry_markdown=(
            "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw): 7-Ring AI agent containment and "
            "breakout prevention runtime in Rust enforcing formal Cedar policies, OS capability sandboxing "
            "(AppContainer/Landlock/WASM), and YARA-X scanning. ![GitHub Repo stars](https://img.shields.io/github/stars/oyesanyf/OshoosiClaw?style=social)"
        ),
        pr_title="Add OshoosiClaw (7-Ring AI Agent Containment & Breakout Prevention Platform)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-ai-security`.\n\n"
            "### AI Security & Agent Containment Architecture\n"
            "- **7-Ring Continuous Cedar Reference Monitor**: Enforces formal Cedar authorization and Z3/SMT-verified policy boundaries around every AI agent tool call.\n"
            "- **OS-Level Capability Sandboxing**: Confines untrusted agent execution via Tier-1 Wasmtime (fuel + 64 MiB linear memory cap) and Tier-2 Windows LowBox AppContainer / Linux seccomp-bpf + Landlock v3.\n"
            "- **Autonomous 4-Arm Research Swarm**: Continuously discovers code-backed arXiv breakout papers (e.g. UK AISI SandboxEscapeBench), extracts grounded indicators via Google LangExtract, and live-tests defenses."
        ),
    ),
    AwesomeListTarget(
        repo="ottosulin/awesome-ai-security",
        vertical=4,
        vertical_name="Specialized Signature (YARA) & Agentic AI Security Lists",
        wave=4,
        category_focus="Agent Runtime Security, Sandboxing & Autonomous EDR",
        target_sections=["Agent Runtime Security & Sandboxing", "Defense & Security Controls", "Tools"],
        entry_markdown=(
            "* [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - _OpenClaw-inspired autonomous security "
            "agent and 7-Ring AI agent containment runtime in Rust. Enforces formal Cedar + SMT policies, "
            "OS-level capability sandboxing (Windows AppContainer, Linux Landlock v3 + seccomp-bpf, Wasmtime), "
            "eBPF/ETW kernel telemetry, and YARA-X scanning._"
        ),
        pr_title="Add OshoosiClaw (Autonomous AI-Driven Rust EDR & Agent Containment Mesh)",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `awesome-ai-cybersecurity`.\n\n"
            "### Key AI + Cybersecurity Capabilities\n"
            "- **Multi-Voter Bayesian Consensus & Clef Decision Engine**: Combines local LLM/ONNX anomaly voters, YARA-X, and kernel behavioral telemetry to eliminate false positives.\n"
            "- **4-Arm LangGraph Security Research Swarm**: Automatically ingests code-backed arXiv security papers, synthesizes Cedar + YARA defenses, and runs live regression probes.\n"
            "- **7-Ring Agentic Breakout Prevention**: Protects AI coding and automation agents against prompt injection, SSRF, and container sandbox escape."
        ),
    ),
    AwesomeListTarget(
        repo="machinae/awesome-claws",
        vertical=4,
        vertical_name="Specialized Signature (YARA) & Agentic AI Security Lists",
        wave=4,
        category_focus="OpenClaw-Inspired Autonomous AI Security & Endpoint Defense Agent",
        target_sections=["Main Projects", "Projects"],
        entry_markdown=(
            "- **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** - Rust - OpenClaw-inspired autonomous "
            "security agent and endpoint defense runtime with kernel-enforced sandboxing, eBPF/ETW telemetry, "
            "YARA-X scanning, and multi-agent containment."
        ),
        pr_title="Add OshoosiClaw",
        pr_body=(
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to **Main Projects** following the `CONTRIBUTING.md` guidelines.\n\n"
            "- **Format**: `- **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** - Rust - OpenClaw-inspired autonomous security agent and endpoint defense runtime with kernel-enforced sandboxing, eBPF/ETW telemetry, YARA-X scanning, and multi-agent containment.`\n"
            "- **Independent Open-Source Project**: Written in Rust (`Apache-2.0`), actively maintained with multi-platform releases (`v1.2.0`)."
        ),
    ),
]


def run_gh_api(endpoint: str, method: str = "GET", payload: Optional[Dict] = None) -> Tuple[int, str]:
    cmd = ["gh", "api", endpoint, "-X", method]
    if payload is not None:
        cmd.extend(["--input", "-"])
        proc = subprocess.run(
            cmd,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
    else:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
    return proc.returncode, proc.stdout.strip() or proc.stderr.strip()


def insert_entry_into_readme(readme_text: str, target: AwesomeListTarget) -> Tuple[str, str]:
    """
    Inserts `target.entry_markdown` under the first matching Markdown section header
    in `target.target_sections`. If OshoosiClaw is already present, returns the text unchanged.
    """
    if "oyesanyf/OshoosiClaw" in readme_text or "OshoosiClaw" in readme_text:
        return readme_text, "already_present"

    lines = readme_text.splitlines()
    matched_section = None
    insert_idx = None

    for sec in target.target_sections:
        header_regex = re.compile(rf"^#{{1,4}}\s+.*?\b{re.escape(sec)}\b.*$", re.IGNORECASE)
        for i, line in enumerate(lines):
            if header_regex.match(line.strip()):
                matched_section = line.strip()
                # Find the end of the bullet list inside this section
                j = i + 1
                last_bullet_idx = None
                while j < len(lines):
                    stripped = lines[j].strip()
                    if stripped.startswith("#"):
                        break
                    if (not lines[j].startswith(("  ", "\t"))) and stripped.startswith(("- [", "* [", "- **[", "* **[", "- :")):
                        last_bullet_idx = j
                        while j + 1 < len(lines) and (lines[j + 1].startswith("  ") or lines[j + 1].startswith("\t")):
                            j += 1
                            last_bullet_idx = j
                    j += 1
                insert_idx = (last_bullet_idx + 1) if last_bullet_idx is not None else (i + 1)
                break
        if insert_idx is not None:
            break

    if insert_idx is None:
        # Fallback: append before License/Contributing or at the end of the file
        matched_section = "Fallback (End of Main List)"
        insert_idx = len(lines)
        for i, line in enumerate(lines):
            if re.match(r"^#{1,3}\s+(Contributing|License|Footnotes)\b", line.strip(), re.IGNORECASE):
                insert_idx = max(0, i - 1)
                break

    entry_line = target.entry_markdown
    # Match bullet character style (`* ` vs `- `) of the surrounding list if applicable
    if insert_idx > 0 and lines[insert_idx - 1].lstrip().startswith("* ") and entry_line.startswith("- "):
        entry_line = "* " + entry_line[2:]
    elif insert_idx > 0 and lines[insert_idx - 1].lstrip().startswith("- ") and entry_line.startswith("* "):
        entry_line = "- " + entry_line[2:]

    new_lines = lines[:insert_idx] + [entry_line] + lines[insert_idx:]
    trailing_newline = "\n" if readme_text.endswith("\n") else ""
    return "\n".join(new_lines) + trailing_newline, matched_section or "Appended"


def check_remote_repo(target: AwesomeListTarget) -> Dict:
    code, out = run_gh_api(f"repos/{target.repo}")
    if code != 0:
        return {
            "repo": target.repo,
            "reachable": False,
            "error": out[:240],
        }
    data = json.loads(out)
    default_branch = data.get("default_branch", "main")
    stars = data.get("stargazers_count", 0)
    archived = data.get("archived", False)

    # Check if an open PR from oyesanyf already exists
    pr_code, pr_out = run_gh_api(f"repos/{target.repo}/pulls?state=open&per_page=100")
    existing_pr_url = None
    if pr_code == 0:
        try:
            pulls = json.loads(pr_out)
            for pr in pulls:
                user_login = (pr.get("user") or {}).get("login", "").lower()
                title = pr.get("title", "")
                if user_login == "oyesanyf" or "oshoosiclaw" in title.lower():
                    existing_pr_url = pr.get("html_url")
                    break
        except Exception:
            pass

    return {
        "repo": target.repo,
        "reachable": True,
        "stars": stars,
        "default_branch": default_branch,
        "archived": archived,
        "existing_pr_url": existing_pr_url,
    }


def submit_pr_for_target(target: AwesomeListTarget, execute: bool = False) -> Dict:
    status = check_remote_repo(target)
    if not status.get("reachable"):
        return {**status, "status": "unreachable"}
    if status.get("archived"):
        return {**status, "status": "skipped_archived"}
    if status.get("existing_pr_url"):
        return {**status, "status": "pr_already_open"}

    # Fetch upstream README via GitHub API
    code, out = run_gh_api(f"repos/{target.repo}/readme")
    if code != 0:
        return {**status, "status": "readme_not_found", "error": out[:200]}

    readme_meta = json.loads(out)
    readme_path = readme_meta.get("path", "README.md")
    readme_sha = readme_meta.get("sha")
    content_b64 = readme_meta.get("content", "")
    readme_text = base64.b64decode(content_b64).decode("utf-8", errors="replace")

    updated_text, matched_section = insert_entry_into_readme(readme_text, target)
    if matched_section == "already_present":
        return {**status, "status": "already_in_readme", "readme_path": readme_path}

    if not execute:
        return {
            **status,
            "status": "dry_run_ready",
            "readme_path": readme_path,
            "matched_section": matched_section,
            "entry_markdown": target.entry_markdown,
            "pr_title": target.pr_title,
        }

    # Execute mode:
    # 1. Fork the repository into the authenticated account
    fork_code, fork_out = run_gh_api(f"repos/{target.repo}/forks", method="POST", payload={})
    if fork_code != 0:
        return {**status, "status": "fork_failed", "error": fork_out[:240]}

    fork_data = json.loads(fork_out)
    fork_full_name = fork_data.get("full_name")
    fork_owner = (fork_data.get("owner") or {}).get("login", "oyesanyf")
    default_branch = status["default_branch"]

    # Wait briefly for GitHub fork provisioning
    time.sleep(2.5)

    # 2. Get base branch SHA in fork
    ref_code, ref_out = run_gh_api(f"repos/{fork_full_name}/git/ref/heads/{default_branch}")
    if ref_code != 0:
        return {**status, "status": "fork_ref_unavailable", "error": ref_out[:240]}
    base_sha = (json.loads(ref_out).get("object") or {}).get("sha")

    branch_name = "add-oshoosiclaw"
    # Create or update branch in fork
    run_gh_api(
        f"repos/{fork_full_name}/git/refs",
        method="POST",
        payload={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
    )

    # Fetch fork README sha on branch
    f_readme_code, f_readme_out = run_gh_api(
        f"repos/{fork_full_name}/contents/{readme_path}?ref={branch_name}"
    )
    fork_readme_sha = readme_sha
    if f_readme_code == 0:
        fork_readme_sha = json.loads(f_readme_out).get("sha", readme_sha)

    # 3. Commit updated README to fork branch
    put_code, put_out = run_gh_api(
        f"repos/{fork_full_name}/contents/{readme_path}",
        method="PUT",
        payload={
            "message": target.pr_title,
            "content": base64.b64encode(updated_text.encode("utf-8")).decode("ascii"),
            "sha": fork_readme_sha,
            "branch": branch_name,
        },
    )
    if put_code != 0:
        return {**status, "status": "commit_failed", "error": put_out[:240]}

    # 4. Open Pull Request against upstream
    pr_code, pr_out = run_gh_api(
        f"repos/{target.repo}/pulls",
        method="POST",
        payload={
            "title": target.pr_title,
            "head": f"{fork_owner}:{branch_name}",
            "base": default_branch,
            "body": target.pr_body,
            "maintainer_can_modify": True,
        },
    )
    if pr_code != 0:
        return {**status, "status": "pr_create_failed", "error": pr_out[:240]}

    pr_created = json.loads(pr_out)
    return {
        **status,
        "status": "pr_opened",
        "pr_url": pr_created.get("html_url"),
        "matched_section": matched_section,
    }


def generate_bundle(output_path: Path, verify_remote: bool = False) -> Dict:
    entries = []
    for t in AWESOME_LIST_TARGETS:
        item = asdict(t)
        if verify_remote:
            item["remote_status"] = check_remote_repo(t)
        entries.append(item)

    bundle = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "canonical_repository": CANONICAL_REPO_URL,
        "canonical_release": CANONICAL_RELEASE_URL,
        "total_targets": len(entries),
        "verticals": {
            "1": "Direct EDR & Detection Engineering",
            "2": "Broad Blue Team, DFIR, Forensics & Reverse Engineering",
            "3": "Rust & eBPF Systems Directories",
            "4": "Specialized Signature (YARA) & Agentic AI Security Lists",
        },
        "targets": entries,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OshoosiClaw 4-Vertical Awesome Lists Traction & PR Automation Script"
    )
    parser.add_argument("--list", action="store_true", help="List all 20 target Awesome Lists across 4 verticals")
    parser.add_argument("--verify-remote", action="store_true", help="Verify remote GitHub repository reachability and existing PR status")
    parser.add_argument("--generate-bundle", action="store_true", help="Generate deploy/awesome-lists-submissions.json")
    parser.add_argument("--submit", action="store_true", help="Prepare or submit PRs to Awesome Lists")
    parser.add_argument("--vertical", type=int, choices=[1, 2, 3, 4], help="Filter by vertical (1..4)")
    parser.add_argument("--repo", type=str, help="Target a single repository (owner/name)")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate README insertion without opening remote PRs (default)")
    parser.add_argument("--execute", action="store_true", help="Actually fork, commit, and open Pull Requests via GitHub API")
    args = parser.parse_args()

    selected = AWESOME_LIST_TARGETS
    if args.vertical is not None:
        selected = [t for t in selected if t.vertical == args.vertical]
    if args.repo:
        selected = [t for t in selected if t.repo.lower() == args.repo.lower()]

    if args.list or (not args.verify_remote and not args.generate_bundle and not args.submit):
        print(f"OshoosiClaw Awesome Lists Traction Matrix ({len(selected)} repositories across 4 verticals)")
        print("=" * 100)
        for v in (1, 2, 3, 4):
            v_items = [t for t in selected if t.vertical == v]
            if not v_items:
                continue
            print(f"\n[Vertical {v}] {v_items[0].vertical_name} (Wave {v_items[0].wave})")
            print("-" * 100)
            for idx, item in enumerate(v_items, 1):
                print(f"  {idx}. {item.repo:<52} | Focus: {item.category_focus}")
                print(f"     Sections: {', '.join(item.target_sections)}")
                print(f"     Entry   : {item.entry_markdown}")

    if args.generate_bundle or args.verify_remote:
        bundle_path = Path("deploy/awesome-lists-submissions.json")
        bundle = generate_bundle(bundle_path, verify_remote=args.verify_remote)
        print(f"\n[+] Wrote {bundle['total_targets']} tailored Awesome List submission specs to {bundle_path}")
        if args.verify_remote:
            for t in bundle["targets"]:
                rs = t.get("remote_status", {})
                print(
                    f"  - {t['repo']:<52} | reachable={rs.get('reachable')} | "
                    f"stars={rs.get('stars', '-')} | existing_pr={rs.get('existing_pr_url')}"
                )

    if args.submit:
        execute_mode = bool(args.execute)
        print(f"\n[+] Running Awesome List submission pipeline (execute={execute_mode}) for {len(selected)} target(s)...")
        results = []
        for t in selected:
            res = submit_pr_for_target(t, execute=execute_mode)
            results.append(res)
            print(
                f"  - {t.repo:<52} -> status={res.get('status')} "
                f"(section={res.get('matched_section', '-')}, pr={res.get('pr_url') or res.get('existing_pr_url') or '-'})"
            )
        out_report = Path("deploy/awesome-lists-last-run.json")
        out_report.parent.mkdir(parents=True, exist_ok=True)
        out_report.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"[+] Saved run report to {out_report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
