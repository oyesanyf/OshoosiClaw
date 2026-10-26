#!/usr/bin/env python3
"""
OshoosiClaw Awesome List PR Preparation & Validation Tool.

Automates formatting, validation, and branch/PR generation for submitting
OshoosiClaw to the top 6 security, systems, and Rust awesome-lists on GitHub.

Usage:
    python scripts/prepare_awesome_prs.py --self-test
    python scripts/prepare_awesome_prs.py --target awesome-rust
    python scripts/prepare_awesome_prs.py --all
"""

import argparse
import sys
from typing import Dict, Any, List

AWESOME_LISTS: Dict[str, Dict[str, Any]] = {
    "awesome-rust": {
        "repo": "rust-unofficial/awesome-rust",
        "file": "README.md",
        "section": "Applications / Security",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized EDR and autonomous immune system with eBPF CO-RE, YARA-X, NASA F' flight OSAL, and TPM 2.0 PCR 16 attestation.",
        "pr_title": "Add OshoosiClaw to Applications / Security",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) under Applications / Security.

OshoosiClaw is an open-source, decentralized Endpoint Detection & Response (EDR) platform written in high-assurance Rust (~77%), featuring:
- eBPF CO-RE Ring-0 probes and Windows ETW/WFP native integration
- NASA JPL F Prime (`F'`) flight-software backbone with static 16MB zero-alloc arena
- Autonomous EDR-Bench dual-gate verification harness (`yara-x`)
- Hardware TPM 2.0 PCR 16 silicon measurements and Ed25519 BFT gossip mesh
- Zero cloud dependencies, MIT license
"""
    },
    "awesome-ebpf": {
        "repo": "zoidbergwill/awesome-ebpf",
        "file": "README.md",
        "section": "Security & Observability",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Autonomous endpoint immune engine using eBPF CO-RE tracepoints for real-time container escape interception and Landlock sandbox fencing.",
        "pr_title": "Add OshoosiClaw to Security & Observability",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) under Security & Observability.

OshoosiClaw utilizes Linux eBPF CO-RE (Compile Once - Run Everywhere) tracepoints (`sys_enter_bpf`, `sched_process_exec`) combined with Rust to detect unprivileged container escapes in Ring-0 and trigger Landlock nanosecond containment.
"""
    },
    "awesome-security": {
        "repo": "sbilly/awesome-security",
        "file": "README.md",
        "section": "Endpoint Detection and Response (EDR)",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized, cloud-free EDR engine featuring Ring-0 kernel drivers, YARA-X synthesis, and automated reverse engineering.",
        "pr_title": "Add OshoosiClaw to Endpoint Detection and Response",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Endpoint Detection and Response (EDR).

OshoosiClaw provides open-source, local-first endpoint defense without cloud lock-in. Features pre-execution blocking, 101-table live SQL telemetry (`Siquery`), and automated binary reverse engineering (`REA`).
"""
    },
    "awesome-threat-intelligence": {
        "repo": "hslatman/awesome-threat-intelligence",
        "file": "README.md",
        "section": "Threat Sharing & Peer-to-Peer Feeds",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized P2P threat mesh sharing STIX 2.1 indicators with ML-KEM-768 post-quantum encryption and TFHE privacy consensus.",
        "pr_title": "Add OshoosiClaw to Threat Sharing & Peer-to-Peer Feeds",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Threat Sharing & Peer-to-Peer Feeds.

OshoosiClaw implements a decentralized P2P STIX 2.1 gossip network secured by ML-KEM-768 post-quantum key exchange and homomorphic voter consensus, allowing endpoints to share high-fidelity threat indicators without centralized aggregators.
"""
    },
    "awesome-ai-security": {
        "repo": "corca-ai/awesome-ai-security",
        "file": "README.md",
        "section": "Agent Defense & LLM Containment",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Fail-closed multi-ring containment for autonomous AI agents, enforcing OWASP Top 10 for Agentic AI, AppContainer, and canary cages.",
        "pr_title": "Add OshoosiClaw to Agent Defense & LLM Containment",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Agent Defense & LLM Containment.

OshoosiClaw provides pre-execution tool gating, semantic trajectory drift tracking, and AppContainer/Job Object isolation for AI worker agents, defending against prompt injections, SSRF, and credential extraction.
"""
    },
    "awesome-incident-response": {
        "repo": "meirwah/awesome-incident-response",
        "file": "README.md",
        "section": "Host Acquisition and Memory Analysis",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Embedded 101-table SQL host telemetry engine (`Siquery`) and autonomous REA binary decompiler for incident response triage.",
        "pr_title": "Add OshoosiClaw to Host Acquisition and Memory Analysis",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Host Acquisition and Memory Analysis.

OshoosiClaw features `Siquery-RS`, an embedded 101-table virtual SQLite engine for querying volatile host artifacts (processes, sockets, drivers, injected modules) paired with `REA` for autonomous decompiler triage.
"""
    },
    "awesome-edr": {
        "repo": "WithSecureLabs/awesome-edr",
        "file": "README.md",
        "section": "Open-Source EDR & Endpoint Agents",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Cross-platform Rust/eBPF CO-RE and Windows WFP/ETW agentic EDR with NASA F' static arena fault-protection and local BFT mesh consensus.",
        "pr_title": "Add OshoosiClaw to Open-Source EDR & Endpoint Agents",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) to Open-Source EDR & Endpoint Agents.
"""
    },
    "awesome-yara": {
        "repo": "InQuest/awesome-yara",
        "file": "README.md",
        "section": "Tools & Automation",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Includes EDR-Bench, a SWE-bench-style YARA-X compiler-in-the-loop verification harness enforcing FAIL_TO_PASS and PASS_TO_PASS zero-FP gates.",
        "pr_title": "Add OshoosiClaw (EDR-Bench YARA-X Harness) to Tools & Automation",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) under Tools & Automation.
"""
    },
    "awesome-llm-security": {
        "repo": "llm-sec/awesome-llm-security",
        "file": "README.md",
        "section": "Agentic Containment & Data Loss Prevention",
        "entry": "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - 7-Ring Cedar reference monitor, Wasmtime/AppContainer sandbox, and OpenTelemetry W3C baggage DLP taint lineage for autonomous AI agents.",
        "pr_title": "Add OshoosiClaw to Agentic Containment & Data Loss Prevention",
        "pr_body": """### Summary
Adds [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) under Agentic Containment & Data Loss Prevention.
"""
    }
}


def validate_entry(target: str, data: Dict[str, Any]) -> List[str]:
    """Validate awesome list entry formatting and constraints."""
    errors = []
    entry = data.get("entry", "")
    if not entry.startswith("- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)"):
        errors.append(f"{target}: Entry must begin with markdown link to repository.")
    if len(entry) > 250:
        errors.append(f"{target}: Entry length ({len(entry)} chars) exceeds 250 character limit.")
    if not data.get("repo"):
        errors.append(f"{target}: Missing target repo.")
    if not data.get("pr_title"):
        errors.append(f"{target}: Missing PR title.")
    if not data.get("pr_body"):
        errors.append(f"{target}: Missing PR body.")
    return errors


def run_self_test() -> int:
    """Run comprehensive validation across all 6 awesome list PR manifests."""
    print("=================================================================")
    print("  OshoosiClaw Awesome-List PR Kit Verification Suite")
    print("=================================================================\n")
    all_ok = True
    for key, data in AWESOME_LISTS.items():
        errs = validate_entry(key, data)
        status = "PASSED" if not errs else "FAILED"
        print(f"[{status}] {key:28} -> {data['repo']} ({data['section']})")
        if errs:
            all_ok = False
            for e in errs:
                print(f"    ERROR: {e}")
        else:
            print(f"    Entry : {data['entry']}")
            print(f"    Title : {data['pr_title']}\n")

    if all_ok:
        print("All 9 awesome list manifests validated cleanly (100% compliant).")
        return 0
    else:
        print("Validation errors encountered.")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="OshoosiClaw Awesome List PR Preparation Tool")
    parser.add_argument("--self-test", action="store_true", help="Validate all awesome list configurations")
    parser.add_argument("--target", type=str, choices=list(AWESOME_LISTS.keys()), help="Target awesome list to inspect")
    parser.add_argument("--all", action="store_true", help="Output PR payloads for all awesome lists")
    args = parser.parse_args()

    if args.self_test or (not args.target and not args.all):
        return run_self_test()

    targets = list(AWESOME_LISTS.keys()) if args.all else [args.target]
    for t in targets:
        data = AWESOME_LISTS[t]
        print(f"\n--- Target: {t} ({data['repo']}) ---")
        print(f"Target Section : {data['section']}")
        print(f"Markdown Entry :\n{data['entry']}\n")
        print(f"PR Title       :\n{data['pr_title']}\n")
        print(f"PR Body        :\n{data['pr_body']}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
