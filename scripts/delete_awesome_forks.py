#!/usr/bin/env python3
"""
delete_awesome_forks.py
=======================
Autonomous cleanup utility to remove all 25 forked third-party "awesome-*" list
repositories (and optionally close any open upstream PRs from those forks) under
the `oyesanyf` GitHub account.

Safety Invariants:
1. NEVER touches any non-forked repository (`isFork == False` verified via GitHub API).
2. Explicit allowlist of the 25 third-party awesome-list forks to remove.
3. Automatically closes any open upstream PRs originating from those forks (uses
   existing `repo` scope immediately).
4. Checks whether the active `gh` CLI token has the `delete_repo` scope required
   by GitHub's REST API (`DELETE /repos/{owner}/{repo}`). If missing, automatically
   launches `gh auth refresh -h github.com -s delete_repo` so you can authorize
   once in your browser, then deletes all 25 forks and verifies removal.

Usage:
    python scripts/delete_awesome_forks.py
    python scripts/delete_awesome_forks.py --dry-run
    python scripts/delete_awesome_forks.py --close-prs-only
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

OWNER = "oyesanyf"

# Exact list of the 25 forked awesome-list repositories cluttering https://github.com/oyesanyf
AWESOME_FORK_REPOS: List[str] = [
    "awesome-rust-security",
    "awesome-openclaw",
    "awesome-openclaw-skills",
    "awesome-agent-skills-security",
    "awesome-agent-control-plane",
    "awesome-claw",
    "awesome-ai-agents",
    "awesome-ai-security-tools",
    "awesome-ai-security",
    "BlueTeam-Tools",
    "awesome-yara",
    "awesome-reversing",
    "awesome-forensics",
    "awesome_Threat-Hunting",
    "awesome-aya",
    "reverse-engineering",
    "awesome-incident-response",
    "awesome-security",
    "awesome-llm-security",
    "awesome-detection-engineering",
    "awesome-ebpf",
    "awesome-cybersecurity-blueteam",
    "awesome-threat-detection",
    "awesome-endpoint-detection-and-response",
    "awesome-claws",
]

# Core repositories that must NEVER be deleted under any circumstance
PROTECTED_REPOS = {
    "OshoosiClaw",
    "MusicFusion",
    "AgentOctopus",
    "killswitch",
    "ModelFusion",
    "RedactX",
    "rfchunt",
    "Edrtest",
    "hugos-ide-vscode",
    "Mechanistic_Interpretability",
    "oyesanyf",
    "ngTaX",
    "Vibe-code-Security-Plugin-for-VsCode-",
    "magicAIcode",
    "nigeria-tax-impact-model",
    "Data_Science_Agent",
    "VaultGemmaSampleCode",
    "ModelSherpa.ai",
    "ModelOrchestrator",
    "femi.oyesanya.io",
    "dlp",
    "homework",
    "test007",
    "testing",
    "tac",
    "ast-eclipse-plugin",
}


def run_cmd(args: List[str], check: bool = False) -> subprocess.CompletedProcess:
    """Run a subprocess command and capture stdout/stderr."""
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )


def get_gh_token() -> Optional[str]:
    """Retrieve the active GitHub token from environment or `gh auth token`."""
    for env_key in ("GH_TOKEN", "GITHUB_TOKEN"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val
    res = run_cmd(["gh", "auth", "token"])
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    return None


def get_token_scopes(token: str) -> List[str]:
    """Inspect X-OAuth-Scopes header from https://api.github.com/user."""
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "OshoosiClaw-Awesome-Cleanup/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            scopes_hdr = resp.headers.get("X-OAuth-Scopes", "")
            return [s.strip() for s in scopes_hdr.split(",") if s.strip()]
    except Exception as exc:
        print(f"[!] Warning: Could not inspect token scopes via REST API: {exc}")
        return []


def github_api_request(
    method: str,
    endpoint: str,
    token: str,
    payload: Optional[Dict] = None,
) -> Tuple[int, Optional[Dict]]:
    """Perform an authenticated GitHub REST API v3 request."""
    url = (
        endpoint
        if endpoint.startswith("https://")
        else f"https://api.github.com/{endpoint.lstrip('/')}"
    )
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "OshoosiClaw-Awesome-Cleanup/1.0",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="replace").strip()
            body = json.loads(raw) if raw else None
            return resp.status, body
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace").strip()
        try:
            body = json.loads(raw) if raw else {"message": str(err)}
        except Exception:
            body = {"message": raw or str(err)}
        return err.code, body
    except Exception as exc:
        return 0, {"message": str(exc)}


def close_open_awesome_prs(token: str, dry_run: bool = False) -> int:
    """Find and close any open PRs created by `oyesanyf` on external awesome-* repos."""
    print("\n[*] Step 1: Checking for open PRs authored by oyesanyf on external awesome-* repos...")
    res = run_cmd(
        [
            "gh",
            "search",
            "prs",
            "--author",
            OWNER,
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "repository,title,url,number",
        ]
    )
    if res.returncode != 0:
        print(f"    [!] Could not search open PRs: {res.stderr.strip()}")
        return 0

    try:
        prs = json.loads(res.stdout)
    except Exception:
        prs = []

    closed_count = 0
    for pr in prs:
        repo_info = pr.get("repository", {})
        repo_name_with_owner = repo_info.get("nameWithOwner", "")
        repo_short = repo_info.get("name", "")
        pr_number = pr.get("number")
        pr_url = pr.get("url", "")
        pr_title = pr.get("title", "")

        # Never touch PRs on oyesanyf's own repositories
        if repo_name_with_owner.lower().startswith(f"{OWNER.lower()}/"):
            continue

        # Target PRs opened against third-party awesome-* / BlueTeam-Tools / reverse-engineering repos
        if (
            repo_short in AWESOME_FORK_REPOS
            or "awesome" in repo_short.lower()
            or repo_short in ("BlueTeam-Tools", "reverse-engineering")
        ):
            if dry_run:
                print(f"    [DRY-RUN] Would close open PR: {pr_url} ({pr_title})")
                continue

            status, body = github_api_request(
                "PATCH",
                f"/repos/{repo_name_with_owner}/pulls/{pr_number}",
                token,
                payload={"state": "closed"},
            )
            if status == 200:
                print(f"    [CLOSED PR] {pr_url} — {pr_title}")
                closed_count += 1
            else:
                msg = (body or {}).get("message", "Unknown error")
                print(f"    [!] Failed to close PR {pr_url} (HTTP {status}): {msg}")

    if closed_count == 0 and not dry_run:
        print("    [+] No open external awesome-list PRs found (or all already closed).")
    return closed_count


def ensure_delete_repo_scope(token: str) -> Optional[str]:
    """Verify `delete_repo` scope is active, or trigger `gh auth refresh` interactively."""
    scopes = get_token_scopes(token)
    print(f"\n[*] Active GitHub Token Scopes: {scopes}")
    if "delete_repo" in scopes:
        print("    [+] 'delete_repo' scope is present! Proceeding with repository deletion.")
        return token

    print("\n[!] Your current GitHub token is missing the 'delete_repo' scope.")
    print("    GitHub requires 'delete_repo' permission to delete forked repositories.")
    print("    Launching: gh auth refresh -h github.com -s delete_repo ...")
    print("    (Please complete the one-time browser authorization prompt if it opens)\n")

    # Run interactively so the user can see the one-time code / browser prompt
    ret = subprocess.call(["gh", "auth", "refresh", "-h", "github.com", "-s", "delete_repo"])
    if ret != 0:
        print("\n[!] `gh auth refresh` did not complete (exit code != 0).")
        return None

    new_token = get_gh_token()
    if not new_token:
        return None
    new_scopes = get_token_scopes(new_token)
    print(f"[*] Updated GitHub Token Scopes: {new_scopes}")
    if "delete_repo" not in new_scopes:
        print("[!] 'delete_repo' scope is still not active.")
        return None
    return new_token


def delete_awesome_forks(token: str, dry_run: bool = False) -> Tuple[int, int, int]:
    """Delete each of the 25 forked awesome-list repositories after verifying `fork == True`."""
    print(f"\n[*] Step 2: Auditing and deleting {len(AWESOME_FORK_REPOS)} awesome-list forks under '{OWNER}'...")
    deleted = 0
    already_gone = 0
    failed = 0

    for repo in AWESOME_FORK_REPOS:
        if repo in PROTECTED_REPOS:
            print(f"    [SKIP-PROTECTED] {OWNER}/{repo} is in PROTECTED_REPOS!")
            continue

        # 1. Check repository metadata first to verify it exists and is a fork
        status, meta = github_api_request("GET", f"/repos/{OWNER}/{repo}", token)
        if status == 404:
            print(f"    [ALREADY DELETED] https://github.com/{OWNER}/{repo}")
            already_gone += 1
            continue
        elif status != 200 or not isinstance(meta, dict):
            msg = (meta or {}).get("message", f"HTTP {status}")
            print(f"    [ERROR] Could not inspect {OWNER}/{repo}: {msg}")
            failed += 1
            continue

        if not meta.get("fork", False):
            print(f"    [SAFETY ABORT] {OWNER}/{repo} is NOT a fork (`fork=False`)! Refusing to delete.")
            continue

        parent_name = (meta.get("parent") or {}).get("full_name", "unknown")
        if dry_run:
            print(f"    [DRY-RUN] Would DELETE fork https://github.com/{OWNER}/{repo} (forked from {parent_name})")
            continue

        # 2. Issue DELETE /repos/{owner}/{repo}
        del_status, del_body = github_api_request("DELETE", f"/repos/{OWNER}/{repo}", token)
        if del_status == 204:
            print(f"    [DELETED] https://github.com/{OWNER}/{repo} (was fork of {parent_name})")
            deleted += 1
        else:
            msg = (del_body or {}).get("message", f"HTTP {del_status}")
            print(f"    [FAILED]  https://github.com/{OWNER}/{repo} -> HTTP {del_status}: {msg}")
            failed += 1

    return deleted, already_gone, failed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete the 25 spam awesome-list forks from https://github.com/oyesanyf"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview which open PRs would be closed and which forked repos would be deleted.",
    )
    parser.add_argument(
        "--close-prs-only",
        action="store_true",
        help="Only close open external awesome-list PRs without deleting forked repositories.",
    )
    parser.add_argument(
        "--skip-prs",
        action="store_true",
        help="Skip checking/closing external PRs and only delete the 25 forked repositories.",
    )
    args = parser.parse_args()

    print("=========================================================================")
    print(f" GitHub Awesome-List Fork & PR Cleanup Utility (Account: {OWNER})")
    print("=========================================================================")

    token = get_gh_token()
    if not token:
        print("[!] ERROR: No GitHub token found. Run `gh auth login` or set GH_TOKEN.")
        return 1

    if not args.skip_prs:
        close_open_awesome_prs(token, dry_run=args.dry_run)

    if args.close_prs_only:
        print("\n[+] Completed `--close-prs-only` pass.")
        return 0

    if not args.dry_run:
        token = ensure_delete_repo_scope(token)
        if not token:
            print(
                "\n[!] Cannot delete repositories until `delete_repo` scope is granted.\n"
                "    Run this command in your terminal to authorize once:\n"
                "        gh auth refresh -h github.com -s delete_repo\n"
                "    Then re-run:\n"
                "        python scripts/delete_awesome_forks.py --skip-prs"
            )
            return 2

    deleted, already_gone, failed = delete_awesome_forks(token, dry_run=args.dry_run)

    print("\n=========================================================================")
    print(f" Summary: Deleted={deleted} | Already Removed={already_gone} | Failed={failed}")
    print("=========================================================================")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
