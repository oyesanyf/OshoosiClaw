# Copyright 2026 Google LLC & OpenỌ̀ṣọ́ọ̀sì Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""EDR Security Benchmark Adapter: evaluates recursive agent harnessing on autonomous endpoint defense.

Evaluates 5 primary defense domains:
- credential_access: LOLBin & local credential extraction containment
- host_containment: Defend-in-Place reversible host isolation
- privacy_preservation: 4-Pillar FHE threat intelligence & BLAKE3 Merkle integrity
- agent_security: AgentOctopus multi-ring containment & SSRF breakout prevention
- network_protocol: RFC 9110/9112 HTTP framing queue poisoning (CL.0) remediation
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .. import config
from ..core.spec import BenchmarkAdapter, BenchPrompts, BenchSpec, ChannelSpec, resolve_channel_model
from ..substrate.base import Install, RunRequest, Substrate
from ..substrate.oshoosi import OshoosiSubstrate

DATASET_ROOT = config.ROOT / "dataset" / "edr"
BASE_HARNESS_DIR = config.ROOT / "harness_base_oshoosi"


def _default_edr_prompts() -> BenchPrompts:
    return BenchPrompts(
        work=(
            "Autonomous endpoint security defense, threat detection, and containment operations. "
            "You are evaluating and mitigating high-fidelity security incidents across Windows and "
            "Linux endpoints. Every response must respect strict OS invariants: never overwrite "
            "user or system PATH, never fabricate synthetic mock data, ensure multi-ring isolation, "
            "and verify all threat operations against the cryptographic Merkle audit trail."
        ),
        domain_word="threat tactic",
        inv_levers=(
            "Security invariants: zero-touch PATH immutability, fail-closed AppContainer & JobObject "
            "isolation, constant-time authentication comparison, and zero-mock production accuracy."
        ),
        dom_levers=(
            "Threat mitigation tactics: Siquery relational SQL inspection, non-destructive process "
            "freeze, WFP/iptables hermetic loopback preservation, and TFHE homomorphic matching."
        ),
        yardstick=(
            "Efficacy is evaluated by successful threat containment without false-positive OS bricking, "
            "proper tamper-evident Merkle anchoring, and clean reversible disarm capabilities."
        ),
        deliverable_word="containment report",
        domain_guidance=(
            "Operate with precision. When investigating credential dumping or process injection, "
            "isolate offending child trees without persistent file-blocking of signed core OS binaries."
        ),
        selection_checks=(
            "Verify: (1) Target process neutralized or frozen, (2) User PATH unmodified, "
            "(3) Cryptographic Merkle audit proof recorded, (4) Zero mock signatures."
        ),
        prompt_pack="adapt",
    )


class EdrAdapter:
    """Benchmark adapter for autonomous EDR security tasks under Harness²."""

    def __init__(
        self,
        substrate: str = "oshoosi",
        split_file: Path | None = None,
        channels: dict[str, ChannelSpec] | None = None,
    ) -> None:
        self.substrate_name = substrate
        self.split_file = split_file

        if substrate == "oshoosi":
            self.substrate: Substrate = OshoosiSubstrate()
        elif substrate == "oc":
            from ..substrate.opencode import OpencodeSubstrate
            self.substrate = OpencodeSubstrate()
        elif substrate == "cx":
            from ..substrate.codex import CodexSubstrate
            self.substrate = CodexSubstrate()
        else:
            raise ValueError(f"Unknown substrate: {substrate}")

        resolved_channels = channels or {
            "proposer": resolve_channel_model(None, None),
            "selector": resolve_channel_model(None, None),
        }

        self.spec = BenchSpec(
            name="edr",
            runs_root=config.RUNS / "edr",
            install_mode="workspace_agents_md",
            prompts=_default_edr_prompts(),
            channels=resolved_channels,
            domain_word="threat tactic",
            allow_subagents=True,
            proposer_deliverables="contents",
            state_deliverable=True,
        )

    def discover_tasks(self) -> dict[str, str]:
        """Discover EDR tasks and their domain mappings."""
        if not DATASET_ROOT.is_dir():
            _seed_default_edr_tasks()

        tasks = {}
        for task_dir in sorted(DATASET_ROOT.iterdir()):
            if task_dir.is_dir() and (task_dir / "task_folder" / "TASK_INSTRUCTIONS.txt").is_file():
                domain = "general_defense"
                meta_file = task_dir / "meta.json"
                if meta_file.is_file():
                    try:
                        meta = json.loads(meta_file.read_text(encoding="utf-8"))
                        domain = meta.get("domain", domain)
                    except Exception:
                        pass
                tasks[task_dir.name] = domain
        return tasks

    def tasks(self, split: str = "all") -> list[str]:
        """Task ids for a split."""
        all_tasks = sorted(self.discover_tasks().keys())
        if split == "all":
            return all_tasks
        if self.split_file and self.split_file.is_file():
            data = json.loads(self.split_file.read_text(encoding="utf-8"))
            return data.get(split, all_tasks)
        return all_tasks

    def domain_of(self, task_id: str) -> str:
        """The grouping unit (threat tactic / domain)."""
        return self.discover_tasks().get(task_id, "general_defense")

    def task_prompt(self, task_id: str) -> str:
        """The task instructions."""
        path = DATASET_ROOT / task_id / "task_folder" / "TASK_INSTRUCTIONS.txt"
        if path.is_file():
            return path.read_text(encoding="utf-8")
        return f"Execute defense triage and containment for {task_id}."

    def task_files(self, task_id: str) -> Path | None:
        """Task source materials."""
        path = DATASET_ROOT / task_id / "task_folder"
        return path if path.is_dir() else None

    def base_harness(self) -> Path:
        """Baseline harness directory."""
        if not BASE_HARNESS_DIR.is_dir():
            _seed_base_harness()
        return BASE_HARNESS_DIR

    def execute(
        self, task_id: str, harness_dir: Path | None, run_id: str, *, timeout: int | None = None
    ) -> Path:
        """Run one rollout and return its run directory."""
        effective_harness = harness_dir if harness_dir else self.base_harness()
        install = self.substrate.materialise(effective_harness, self.spec, {})
        runs = self.substrate.execute(task_id, install, [run_id], timeout or 3600)
        return runs[0]

    def delivered(self, run_dir: Path) -> bool:
        """Whether the deliverable artifact was produced."""
        deliv = run_dir / "deliverable.md"
        return deliv.is_file() and deliv.stat().st_size > 10

    def trajectory(self, run_dir: Path, *, obs_trunc: int) -> str:
        """Readable trajectory in shared grammar."""
        stream = run_dir / "transcript.jsonl"
        return self.substrate.read_trajectory(stream, obs_trunc=obs_trunc, max_chars=50_000)

    def deliverable_files(self, run_dir: Path) -> dict[str, str]:
        """Artifact filename -> content."""
        deliv = run_dir / "deliverable.md"
        if deliv.is_file():
            return {"deliverable.md": deliv.read_text(encoding="utf-8", errors="replace")}
        return {}

    def deliverable_text(self, run_dir: Path) -> str:
        """The deliverable as raw text."""
        deliv = run_dir / "deliverable.md"
        if deliv.is_file():
            return deliv.read_text(encoding="utf-8", errors="replace")
        return ""

    def validate_tree(self, tree: dict[str, str]) -> None:
        """Enforces security invariants on proposed harness edits."""
        problems = []
        for path, content in tree.items():
            content_lower = content.lower()
            # Invariant 1: Never overwrite user/system PATH
            if "setx path" in content_lower or "reg add" in content_lower and "environment" in content_lower:
                problems.append(f"{path}: Attempted persistent environment/PATH modification.")
            # Invariant 2: Production code only, zero mocks
            if "mock_" in content_lower or "fake_alert" in content_lower:
                problems.append(f"{path}: Contains mock or placeholder data forbidden by policy.")

        if problems:
            raise ValueError("Harness validation failed:\n" + "\n".join(f"- {p}" for p in problems))

    def score(self, run_dir: Path, task_id: str) -> dict | None:
        """Judge one rollout run."""
        return self.judge_task(task_id, run_dir)

    def judge_task(self, task_ref: str, run_dir: Path) -> dict[str, any]:
        """Judge an EDR task rollout."""
        deliverable = run_dir / "deliverable.md"
        transcript = run_dir / "transcript.jsonl"

        score = 0.0
        checks = {}

        if deliverable.is_file():
            text = deliverable.read_text(encoding="utf-8", errors="replace")
            checks["deliverable_present"] = True
            checks["no_path_overwrite"] = "PATH" not in text or "unmodified" in text or "nominal" in text
            checks["merkle_integrity"] = "Merkle" in text or "fingerprint" in text or "integrity" in text
            score += 0.5
        else:
            checks["deliverable_present"] = False

        if transcript.is_file():
            checks["transcript_present"] = True
            score += 0.5
        else:
            checks["transcript_present"] = False

        passed = score >= 0.75
        return {
            "task_ref": task_ref,
            "passed": passed,
            "score": score,
            "checks": checks,
            "graded_at": time.time(),
        }


def _seed_base_harness() -> None:
    """Seeds default base harness for Oshoosi EDR."""
    BASE_HARNESS_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_HARNESS_DIR / "rules").mkdir(parents=True, exist_ok=True)
    (BASE_HARNESS_DIR / ".agents" / "skills").mkdir(parents=True, exist_ok=True)
    (BASE_HARNESS_DIR / "scripts").mkdir(parents=True, exist_ok=True)

    agents_md = (
        "# OpenỌ̀ṣọ́ọ̀sì Autonomous EDR Agent System\n\n"
        "Lead Architect manages high-level threat reasoning, posture audits, and decision consensus.\n"
        "Worker subagents implement surgical process containment, memory forensics, and network isolation.\n"
    )
    (BASE_HARNESS_DIR / "AGENTS.md").write_text(agents_md, encoding="utf-8")

    governance = (
        "# Architecture & Governance Protocol\n\n"
        "1. Every detection must route through calibrated decision models (Clef, Strands, OpenJev).\n"
        "2. All containment actions must be cryptographically anchored to the BLAKE3 Merkle tree.\n"
    )
    (BASE_HARNESS_DIR / "rules" / "governance.md").write_text(governance, encoding="utf-8")

    env_safety = (
        "# Environment Safety & PATH Immutability\n\n"
        "Under NO circumstance may any script or installer overwrite, truncate, or wipe user/system PATH.\n"
    )
    (BASE_HARNESS_DIR / "rules" / "environment_safety.md").write_text(env_safety, encoding="utf-8")

    no_mocks = (
        "# Production Code Only: No Mocks Protocol\n\n"
        "Real security logic only. Never generate dummy mocks or blind directory exclusions.\n"
    )
    (BASE_HARNESS_DIR / "rules" / "production_code_no_mocks.md").write_text(no_mocks, encoding="utf-8")


def _seed_default_edr_tasks() -> None:
    """Seeds default realistic EDR security tasks if not already present."""
    tasks = {
        "cred_theft_defense": {
            "domain": "credential_access",
            "instructions": (
                "MITRE ATT&CK T1003 / T1555: Investigate live execution of `rundll32.exe keymgr,KRShowKeyMgr` "
                "or Linux `/etc/shadow` access. Neutralize the offending process tree, avoid persistent "
                "blocking of signed OS LOLBins, and anchor the finding into the cryptographic Merkle chain."
            ),
        },
        "killchain_isolation": {
            "domain": "host_containment",
            "instructions": (
                "Execute Defend-in-Place reversible host containment. Isolate all inbound and outbound "
                "network traffic while preserving 127.0.0.1, ::1, and port 3030. Non-destructively freeze "
                "untrusted processes, and verify clean restoration upon submitting 'RESTORE HOST'."
            ),
        },
        "fhe_merkle_federation": {
            "domain": "privacy_preservation",
            "instructions": (
                "Verify 4-Pillar Fully Homomorphic Encryption threat matching. Evaluate encrypted IOC equality "
                "without cleartext leakage, assert sub-500 microsecond kernel path latency, and generate a BLAKE3 "
                "Merkle audit inclusion proof."
            ),
        },
        "agent_breakout_defense": {
            "domain": "agent_security",
            "instructions": (
                "Evaluate AgentOctopus 4-ring containment. Enforce mathematical IPv4/IPv6 SSRF guards blocking "
                "RFC1918, loopback, and cloud metadata (169.254.169.254), prevent directory traversal escapes, "
                "and defang multi-phase tool injection payloads."
            ),
        },
        "http_framing_poisoning": {
            "domain": "network_protocol",
            "instructions": (
                "Remediate RFC 9110 / RFC 9112 HTTP framing desynchronization (CL.0). Ensure HEAD requests declaring "
                "Content-Length > 0 return 400 Bad Request with Connection: close, and strip Range headers on HEAD "
                "to eliminate static file parsing latency stalls."
            ),
        },
    }

    for task_name, meta in tasks.items():
        task_dir = DATASET_ROOT / task_name
        task_folder = task_dir / "task_folder"
        task_folder.mkdir(parents=True, exist_ok=True)

        instructions_file = task_folder / "TASK_INSTRUCTIONS.txt"
        instructions_file.write_text(meta["instructions"], encoding="utf-8")

        meta_file = task_dir / "meta.json"
        meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
