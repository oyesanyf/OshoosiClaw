#!/usr/bin/env python3
"""
OshoosiClaw — Milestone M15 Awesome Lists Submissions & Fork SEO Indexing Script
==============================================================================
Submits genuine upstream PRs and synchronizes fork landing pages (default branches)
across all 9 targeted Awesome List repositories for Milestone M15:
  1. Ar9av/awesome-agent-control-plane
  2. scadastrangelove/awesome-ai-security-tools
  3. aloth/awesome-ai-agents
  4. ottosulin/awesome-ai-security
  5. andar1an/awesome-rust-security-vendor
  6. andrijdavid/awesome-claw (data/repos.json + README.md)
  7. LLMSecurity/awesome-agent-skills-security
  8. VoltAgent/awesome-openclaw-skills
  9. vincentkoc/awesome-openclaw
"""

import base64
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8")


def gh_api(endpoint: str, method: str = "GET", payload: Optional[Dict] = None) -> Tuple[int, str]:
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


def ensure_fork(upstream_repo: str) -> Tuple[str, str]:
    """Ensures upstream_repo is forked under oyesanyf. Returns (fork_full_name, default_branch)."""
    repo_name = upstream_repo.split("/")[-1]
    fork_full = f"oyesanyf/{repo_name}"

    # Check if fork already exists
    code, out = gh_api(f"repos/{fork_full}")
    if code == 0:
        data = json.loads(out)
        return fork_full, data.get("default_branch", "main")

    # If not, fork it
    print(f"[*] Forking {upstream_repo} -> {fork_full}...")
    fcode, fout = gh_api(f"repos/{upstream_repo}/forks", method="POST", payload={})
    if fcode != 0:
        raise RuntimeError(f"Fork failed for {upstream_repo}: {fout}")

    # Wait for fork provisioning
    for _ in range(12):
        time.sleep(2.5)
        code, out = gh_api(f"repos/{fork_full}")
        if code == 0:
            data = json.loads(out)
            return fork_full, data.get("default_branch", "main")

    raise TimeoutError(f"Fork {fork_full} provisioning timed out")


def get_ref_sha(repo: str, branch: str) -> str:
    code, out = gh_api(f"repos/{repo}/git/ref/heads/{branch}")
    if code != 0:
        raise RuntimeError(f"Failed to get ref for {repo} heads/{branch}: {out}")
    data = json.loads(out)
    return data["object"]["sha"]


def ensure_branch(repo: str, branch_name: str, base_sha: str) -> str:
    code, out = gh_api(f"repos/{repo}/git/ref/heads/{branch_name}")
    if code == 0:
        data = json.loads(out)
        return data["object"]["sha"]

    print(f"[*] Creating branch {branch_name} on {repo} at {base_sha[:8]}...")
    ccode, cout = gh_api(
        f"repos/{repo}/git/refs",
        method="POST",
        payload={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
    )
    if ccode != 0:
        raise RuntimeError(f"Failed to create branch {branch_name} on {repo}: {cout}")
    data = json.loads(cout)
    return data["object"]["sha"]


def get_file_content_and_sha(repo: str, file_path: str, branch: str) -> Tuple[str, str]:
    code, out = gh_api(f"repos/{repo}/contents/{file_path}?ref={branch}")
    if code != 0:
        raise RuntimeError(f"Failed to get {file_path} from {repo} (branch {branch}): {out}")
    data = json.loads(out)
    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return content, data["sha"]


def commit_file(repo: str, file_path: str, content: str, sha: str, branch: str, message: str) -> str:
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    payload = {
        "message": message,
        "content": b64,
        "sha": sha,
        "branch": branch,
    }
    code, out = gh_api(f"repos/{repo}/contents/{file_path}", method="PUT", payload=payload)
    if code != 0:
        raise RuntimeError(f"Failed to commit {file_path} to {repo} ({branch}): {out}")
    data = json.loads(out)
    return data["commit"]["sha"]


def get_or_create_upstream_pr(upstream_repo: str, head_branch: str, base_branch: str, title: str, body: str) -> str:
    # Check if PR already open
    code, out = gh_api(f"repos/{upstream_repo}/pulls?state=open&per_page=100")
    if code == 0:
        pulls = json.loads(out)
        for p in pulls:
            if (p.get("user") or {}).get("login") == "oyesanyf" or "oshoosi" in p.get("title", "").lower():
                return p.get("html_url")

    # Create new PR
    print(f"[*] Opening upstream PR to {upstream_repo} from oyesanyf:{head_branch}...")
    payload = {
        "title": title,
        "head": f"oyesanyf:{head_branch}",
        "base": base_branch,
        "body": body,
        "maintainer_can_modify": True,
    }
    pcode, pout = gh_api(f"repos/{upstream_repo}/pulls", method="POST", payload=payload)
    if pcode != 0:
        raise RuntimeError(f"Failed to create PR against {upstream_repo}: {pout}")
    data = json.loads(pout)
    return data["html_url"]


# =============================================================================
# REPO-SPECIFIC PATCH LOGIC
# =============================================================================

def patch_ar9av(readme: str) -> str:
    """Ar9av/awesome-agent-control-plane: Add to Policy Enforcement & Runtime Control and Sandboxing & Isolation."""
    lines = readme.splitlines()

    # 1. Policy Enforcement & Runtime Control
    entry_policy = "- **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** - Decentralized Rust EDR and 7-Ring AI agent control plane enforcing formal Cedar policies, behavioral drift tracking, out-of-sandbox credential sealing, and multi-voter consensus."
    # 2. Sandboxing & Isolation
    entry_sandbox = "- **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** - Cross-platform AI agent containment runtime providing zero-overhead Wasmtime, Windows AppContainer, and Linux Landlock v3 + seccomp-bpf sandboxing for autonomous agent tool execution."

    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)
        if "## 🚧 Policy Enforcement & Runtime Control" in line:
            # find end of bullets
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("## "):
                new_lines.append(lines[j])
                j += 1
            # insert entry before next section
            if entry_policy not in new_lines:
                new_lines.append(entry_policy)
            i = j - 1
        elif "## 📦 Sandboxing & Isolation" in line:
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("## "):
                new_lines.append(lines[j])
                j += 1
            if entry_sandbox not in new_lines:
                new_lines.append(entry_sandbox)
            i = j - 1
        i += 1

    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


def patch_scadastrangelove(readme: str) -> str:
    """scadastrangelove/awesome-ai-security-tools: Add under ### Runtime Protection & Enforcement."""
    entry = "- **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** 🟢 — Decentralized Rust EDR and 7-Ring AI agent containment engine enforcing formal Cedar policies, zero-overhead Wasmtime and OS capability sandboxes (Windows AppContainer, Linux Landlock v3 + seccomp-bpf), out-of-sandbox credential sealing, and YARA-X scanning. *(oyesanyf)* — **note:** cross-platform (Windows, Linux, macOS), open-source (Apache-2.0), signed releases with SLSA provenance."
    if "OshoosiClaw" in readme:
        return readme
    lines = readme.splitlines()
    new_lines = []
    inserted = False
    for i, line in enumerate(lines):
        new_lines.append(line)
        if not inserted and line.strip() == "### Runtime Protection & Enforcement":
            new_lines.append("")
            new_lines.append(entry)
            inserted = True
    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


def patch_aloth(readme: str) -> str:
    """aloth/awesome-ai-agents: Add under ### Sandboxing & Execution."""
    entry = "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) — Decentralized Rust EDR and 7-Ring AI agent containment engine with AppContainer / Landlock v3 + seccomp-bpf sandboxing, out-of-sandbox credential sealing, and formal Cedar policies. Apache-2.0."
    if "OshoosiClaw" in readme:
        return readme
    lines = readme.splitlines()
    new_lines = []
    inserted = False
    for i, line in enumerate(lines):
        new_lines.append(line)
        if not inserted and line.strip() == "### Sandboxing & Execution":
            new_lines.append(entry)
            inserted = True
    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


def patch_andar1an(readme: str) -> str:
    """andar1an/awesome-rust-security-vendor: Add under ## Threat Detection and Forensics."""
    entry = "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized Rust EDR and 7-Ring AI agent containment engine with eBPF/ETW kernel telemetry, YARA-X scanning, and AppContainer/Landlock sandbox isolation."
    if "OshoosiClaw" in readme:
        return readme
    lines = readme.splitlines()
    new_lines = []
    inserted = False
    for i, line in enumerate(lines):
        new_lines.append(line)
        if not inserted and line.strip() == "## Threat Detection and Forensics":
            new_lines.append("")
            new_lines.append(entry)
            inserted = True
    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


def patch_awesome_claw_json(json_text: str) -> str:
    """andrijdavid/awesome-claw: Add to data/repos.json openclawForks."""
    data = json.loads(json_text)
    forks = data.get("openclawForks", [])
    for f in forks:
        if f.get("name") == "OshoosiClaw" or "oyesanyf/OshoosiClaw" in f.get("url", ""):
            return json_text
    entry = {
        "name": "OshoosiClaw",
        "owner": "oyesanyf",
        "repo": "OshoosiClaw",
        "url": "https://github.com/oyesanyf/OshoosiClaw",
        "description": "Decentralized Rust EDR and 7-Ring AI agent containment engine with AppContainer/Landlock sandboxing and YARA-X scanning."
    }
    forks.append(entry)
    data["openclawForks"] = forks
    return json.dumps(data, indent=2) + "\n"


def patch_awesome_claw_readme(readme: str) -> str:
    """andrijdavid/awesome-claw: Add to README.md under ### OpenClaw Forks."""
    entry = "- [OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) ![GitHub Repo stars](https://img.shields.io/github/stars/oyesanyf/OshoosiClaw?style=flat-square) - Decentralized Rust EDR and 7-Ring AI agent containment engine with AppContainer/Landlock sandboxing and YARA-X scanning."
    if "OshoosiClaw" in readme:
        return readme
    lines = readme.splitlines()
    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if not inserted and line.strip() == "### OpenClaw Forks":
            new_lines.append("")
            new_lines.append(entry)
            inserted = True
    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


def patch_llmsecurity(readme: str) -> str:
    """LLMSecurity/awesome-agent-skills-security: Add to ## Tools & Frameworks table."""
    row = "| **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** | Decentralized Rust EDR and 7-Ring AI agent containment runtime enforcing formal Cedar policies, zero-overhead Wasmtime + OS capability sandboxes (Windows AppContainer / Linux Landlock v3 + seccomp-bpf), out-of-sandbox credential sealing, and YARA-X skill/memory scanning | [![GitHub](https://img.shields.io/github/stars/oyesanyf/OshoosiClaw)](https://github.com/oyesanyf/OshoosiClaw) |"
    if "OshoosiClaw" in readme:
        return readme
    lines = readme.splitlines()
    new_lines = []
    inserted = False
    for i, line in enumerate(lines):
        new_lines.append(line)
        if not inserted and line.strip().startswith("|") and "| Tool | Description | Link |" in line:
            # find the header separator |------|...
            if i + 1 < len(lines):
                new_lines.append(lines[i + 1])
                new_lines.append(row)
                inserted = True
                # Skip the next line in normal iteration since we appended it
    # If not matched header specifically, fallback after ## Tools & Frameworks
    if not inserted:
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if not inserted and line.strip() == "## Tools & Frameworks":
                new_lines.append("")
                new_lines.append(row)
                inserted = True

    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


def patch_voltagent(readme: str) -> str:
    """VoltAgent/awesome-openclaw-skills: Add under ## Security Notice -> **Recommended tools:**."""
    entry = "- [OshoosiClaw (OpenOsoosi)](https://github.com/oyesanyf/OshoosiClaw) - Decentralized Rust EDR and 7-Ring AI agent containment engine for sandboxing untrusted OpenClaw skills, sealing API keys out-of-band, and scanning skill payloads with YARA-X."
    if "OshoosiClaw" in readme:
        return readme
    lines = readme.splitlines()
    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if not inserted and line.strip() == "**Recommended tools:**":
            new_lines.append("")
            new_lines.append(entry)
            inserted = True
    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


def patch_vincentkoc(readme: str) -> str:
    """vincentkoc/awesome-openclaw: Add under ## Alternative Architectures."""
    entry = "- [oyesanyf/OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw) - Decentralized Rust EDR and 7-Ring AI agent containment security engine for the OpenClaw ecosystem. ![GitHub stars](https://img.shields.io/github/stars/oyesanyf/OshoosiClaw?style=social)"
    if "OshoosiClaw" in readme:
        return readme
    lines = readme.splitlines()
    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if not inserted and line.strip() == "## Alternative Architectures":
            new_lines.append("")
            new_lines.append(entry)
            inserted = True
    return "\n".join(new_lines) + ("\n" if readme.endswith("\n") else "")


# =============================================================================
# MAIN PROCESSOR
# =============================================================================

TARGET_DEFINITIONS = [
    {
        "repo": "Ar9av/awesome-agent-control-plane",
        "patch_func": patch_ar9av,
        "pr_title": "Add OshoosiClaw (7-Ring Cedar Policy Enforcement & Capability Sandboxing)",
        "pr_body": (
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `## 🚧 Policy Enforcement & Runtime Control` and `## 📦 Sandboxing & Isolation`.\n\n"
            "### Control Plane Capabilities\n"
            "- **Formal Cedar Policy Enforcement**: 7-Ring continuous reference monitor evaluating Cedar authorization policies over agent tool calls, network requests, and IPC messages before execution.\n"
            "- **Multi-OS Sandboxing & Isolation**: Zero-overhead Wasmtime capability runtime, Windows AppContainer / Job Object sandboxing, and Linux Landlock v3 + seccomp-bpf system call filtering.\n"
            "- **Decentralized & Host-Native**: High-assurance Rust engine with eBPF/ETW kernel telemetry, behavioral anomaly detection, and out-of-sandbox credential sealing."
        ),
    },
    {
        "repo": "scadastrangelove/awesome-ai-security-tools",
        "patch_func": patch_scadastrangelove,
        "pr_title": "Add OshoosiClaw to Runtime Protection & Enforcement",
        "pr_body": (
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** under `### Runtime Protection & Enforcement`.\n\n"
            "### Highlights\n"
            "- **7-Ring Containment**: Continuous Cedar policy reference monitor preventing prompt injection breakouts and unauthorized tool invocations.\n"
            "- **Kernel & Sandbox Confinement**: Native Windows AppContainer / Job Objects and Linux Landlock v3 / seccomp-bpf containment with out-of-band credential sealing.\n"
            "- **Cross-Platform & Signed**: Production Rust engine with ETW/Minifilter and eBPF CO-RE sensors, YARA-X memory scanning, and SLSA provenance attestations."
        ),
    },
    {
        "repo": "aloth/awesome-ai-agents",
        "patch_func": patch_aloth,
        "pr_title": "Add OshoosiClaw to Sandboxing & Execution",
        "pr_body": (
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `### Sandboxing & Execution`.\n\n"
            "### Features\n"
            "- Sandboxing runtime for AI agents with Windows AppContainer and Linux Landlock v3 / seccomp-bpf isolation.\n"
            "- 7-Ring Continuous Cedar Reference Monitor for tool call authorization and credential sealing.\n"
            "- Open source (Apache-2.0), written in high-performance Rust."
        ),
    },
    {
        "repo": "ottosulin/awesome-ai-security",
        "already_handled": True,
        "existing_pr": "https://github.com/ottosulin/awesome-ai-security/pull/616",
    },
    {
        "repo": "andar1an/awesome-rust-security-vendor",
        "patch_func": patch_andar1an,
        "pr_title": "Add OshoosiClaw to Threat Detection and Forensics",
        "pr_body": (
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `## Threat Detection and Forensics`.\n\n"
            "### Why OshoosiClaw Fits\n"
            "- High-assurance Rust workspace (~34 crates) implementing an open-source, decentralized EDR and AI agent security runtime.\n"
            "- Native eBPF CO-RE (Linux) and ETW / Minifilter (Windows) telemetry.\n"
            "- Integrated YARA-X scanning, MITRE ATT&CK behavioral correlation, and Landlock/AppContainer capability sandboxing."
        ),
    },
    {
        "repo": "andrijdavid/awesome-claw",
        "is_awesome_claw": True,
        "pr_title": "Add OshoosiClaw to OpenClaw Forks",
        "pr_body": (
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to `data/repos.json` and `README.md` under `### OpenClaw Forks`.\n\n"
            "### Overview\n"
            "- **Name**: OshoosiClaw\n"
            "- **Repository**: https://github.com/oyesanyf/OshoosiClaw\n"
            "- **Description**: Decentralized Rust EDR and 7-Ring AI agent containment engine with AppContainer/Landlock sandboxing and YARA-X scanning."
        ),
    },
    {
        "repo": "LLMSecurity/awesome-agent-skills-security",
        "patch_func": patch_llmsecurity,
        "pr_title": "Add OshoosiClaw to Tools & Frameworks table",
        "pr_body": (
            "## Summary\n"
            "Adds **[OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** to the `## Tools & Frameworks` table.\n\n"
            "### Description\n"
            "Decentralized Rust EDR and 7-Ring AI agent containment runtime enforcing formal Cedar policies, zero-overhead Wasmtime + OS capability sandboxes (Windows AppContainer / Linux Landlock v3 + seccomp-bpf), out-of-sandbox credential sealing, and YARA-X skill/memory scanning."
        ),
    },
    {
        "repo": "VoltAgent/awesome-openclaw-skills",
        "patch_func": patch_voltagent,
        "pr_title": "Add OshoosiClaw to Security Notice Recommended Tools",
        "pr_body": (
            "## Summary\n"
            "Adds **[OshoosiClaw (OpenOsoosi)](https://github.com/oyesanyf/OshoosiClaw)** under `## Security Notice` -> `**Recommended tools:**`.\n\n"
            "### Purpose\n"
            "Provides decentralized Rust EDR and 7-Ring AI agent containment engine for sandboxing untrusted OpenClaw skills, sealing API keys out-of-band, and scanning skill payloads with YARA-X."
        ),
    },
    {
        "repo": "vincentkoc/awesome-openclaw",
        "patch_func": patch_vincentkoc,
        "pr_title": "Add OshoosiClaw to Alternative Architectures",
        "pr_body": (
            "## Summary\n"
            "Adds **[oyesanyf/OshoosiClaw](https://github.com/oyesanyf/OshoosiClaw)** under `## Alternative Architectures`.\n\n"
            "### Details\n"
            "Decentralized Rust EDR and 7-Ring AI agent containment security engine for the OpenClaw ecosystem, featuring multi-OS capability sandboxing, formal Cedar policies, and eBPF/ETW kernel telemetry."
        ),
    },
]


def process_target(t: Dict) -> Dict:
    repo = t["repo"]
    print(f"\n=======================================================")
    print(f" Processing: {repo}")
    print(f"=======================================================")

    if t.get("already_handled"):
        print(f"[+] Already handled: PR is {t['existing_pr']}, fork main updated.")
        return {
            "repo": repo,
            "status": "success",
            "pr_url": t["existing_pr"],
            "fork_url": "https://github.com/oyesanyf/awesome-ai-security",
            "default_branch": "main",
            "seo_synced": True,
        }

    # Step 1: Ensure fork
    fork_full, default_branch = ensure_fork(repo)
    print(f"[+] Fork verified: {fork_full} (default branch: {default_branch})")

    # Step 2: Ensure branch add-oshoosiclaw
    base_sha = get_ref_sha(fork_full, default_branch)
    branch_name = "add-oshoosiclaw"
    ensure_branch(fork_full, branch_name, base_sha)

    # Step 3: Patch content on branch add-oshoosiclaw
    if t.get("is_awesome_claw"):
        # andrijdavid/awesome-claw needs data/repos.json AND README.md
        print(f"[*] Patching data/repos.json on {branch_name}...")
        j_content, j_sha = get_file_content_and_sha(fork_full, "data/repos.json", branch_name)
        new_j = patch_awesome_claw_json(j_content)
        commit_file(
            fork_full,
            "data/repos.json",
            new_j,
            j_sha,
            branch_name,
            "Add OshoosiClaw to data/repos.json openclawForks",
        )

        print(f"[*] Patching README.md on {branch_name}...")
        r_content, r_sha = get_file_content_and_sha(fork_full, "README.md", branch_name)
        new_r = patch_awesome_claw_readme(r_content)
        commit_file(
            fork_full,
            "README.md",
            new_r,
            r_sha,
            branch_name,
            t["pr_title"],
        )

        # Step 4: Open Upstream PR
        pr_url = get_or_create_upstream_pr(
            repo, branch_name, default_branch, t["pr_title"], t["pr_body"]
        )
        print(f"[+] Upstream PR opened / active: {pr_url}")

        # Step 5: SEO sync to default branch
        print(f"[*] CRITICAL SEO: Syncing changes to default branch ({default_branch})...")
        main_j_content, main_j_sha = get_file_content_and_sha(fork_full, "data/repos.json", default_branch)
        new_main_j = patch_awesome_claw_json(main_j_content)
        commit_file(
            fork_full,
            "data/repos.json",
            new_main_j,
            main_j_sha,
            default_branch,
            "Add OshoosiClaw to data/repos.json openclawForks (SEO landing page)",
        )

        main_r_content, main_r_sha = get_file_content_and_sha(fork_full, "README.md", default_branch)
        new_main_r = patch_awesome_claw_readme(main_r_content)
        commit_file(
            fork_full,
            "README.md",
            new_main_r,
            main_r_sha,
            default_branch,
            f"{t['pr_title']} (SEO landing page)",
        )

    else:
        # README.md only
        print(f"[*] Patching README.md on {branch_name}...")
        content, sha = get_file_content_and_sha(fork_full, "README.md", branch_name)
        new_content = t["patch_func"](content)
        commit_file(
            fork_full,
            "README.md",
            new_content,
            sha,
            branch_name,
            t["pr_title"],
        )

        # Step 4: Open Upstream PR
        pr_url = get_or_create_upstream_pr(
            repo, branch_name, default_branch, t["pr_title"], t["pr_body"]
        )
        print(f"[+] Upstream PR opened / active: {pr_url}")

        # Step 5: SEO sync to default branch
        print(f"[*] CRITICAL SEO: Syncing changes to default branch ({default_branch})...")
        main_content, main_sha = get_file_content_and_sha(fork_full, "README.md", default_branch)
        new_main_content = t["patch_func"](main_content)
        commit_file(
            fork_full,
            "README.md",
            new_main_content,
            main_sha,
            default_branch,
            f"{t['pr_title']} (SEO landing page)",
        )

    print(f"[SUCCESS] {repo} completed! PR: {pr_url}, SEO fork: https://github.com/{fork_full}")
    return {
        "repo": repo,
        "status": "success",
        "pr_url": pr_url,
        "fork_url": f"https://github.com/{fork_full}",
        "default_branch": default_branch,
        "seo_synced": True,
    }


def main():
    print("=================================================================")
    print("  OshoosiClaw Milestone M15: Awesome Lists Submissions & SEO Engine")
    print("=================================================================\n")

    results = []
    for t in TARGET_DEFINITIONS:
        try:
            res = process_target(t)
            results.append(res)
        except Exception as e:
            print(f"[ERROR] Failed processing {t['repo']}: {e}")
            results.append({
                "repo": t["repo"],
                "status": "error",
                "error": str(e),
            })

    report_path = Path("deploy/awesome_m15_submissions.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[+] Saved submission summary to {report_path}")

    # Summary table
    print("\n" + "=" * 110)
    print(f"{'Repository':<42} | {'Status':<8} | {'Upstream PR':<36} | {'Fork URL'}")
    print("=" * 110)
    for r in results:
        repo = r["repo"]
        status = r["status"]
        pr = r.get("pr_url", "-")
        fork = r.get("fork_url", "-")
        print(f"{repo:<42} | {status:<8} | {pr:<36} | {fork}")
    print("=" * 110)


if __name__ == "__main__":
    main()
