"""
Triage & Blast Radius Agent for LangGraph Defense Swarm.
Evaluates process lineage, command line signatures, and compiler/IDE whitelists
to isolate false positives and compute blast radius before forensic engagement.
"""

from typing import Dict, Any
from ..state import DefenseState

KNOWN_IDE_BUILD_BINARIES = {
    "cargo.exe", "rustc.exe", "cl.exe", "link.exe", "msbuild.exe",
    "git.exe", "code.exe", "devenv.exe", "python.exe", "node.exe",
    "cargo", "rustc", "git", "python3", "node"
}

KNOWN_DEV_DIRECTORIES = [
    r"\target\debug", r"\target\release", r"\node_modules",
    r"\.cargo", r"\.rustup", r"\.vscode", r"\AppData\Local\Programs\Microsoft VS Code"
]

MALICIOUS_CMD_INDICATORS = [
    "-enc", "powershell -e", "vssadmin delete shadows", "wmic shadowcopy delete",
    "bcedit /set", "invoke-mimikatz", "sekurlsa::", "lsass", "procdump",
    "rundll32.exe #", "certutil -urlcache -f", "bitsadmin /transfer"
]


def is_ide_or_dev_workload(path: str, proc_name: str) -> bool:
    name_lower = proc_name.lower().strip()
    path_lower = path.lower().strip()

    if name_lower in KNOWN_IDE_BUILD_BINARIES:
        # Check if executed within developer directory or clean target
        if any(d.lower() in path_lower for d in KNOWN_DEV_DIRECTORIES):
            return True

    return False


def evaluate_blast_radius(state: DefenseState) -> float:
    score = 0.3  # Base baseline
    cmd = (state.get("command_line") or "").lower()
    proc = (state.get("target_process_name") or "").lower()
    pid = state.get("target_pid", 0)

    # Core system process proximity increases blast radius
    if pid < 1000 and pid not in (0, 1, 4):
        score += 0.25

    # Process names mimicking critical services
    if proc in ["svchost.exe", "explorer.exe", "spoolsv.exe", "lsass.exe"]:
        score += 0.2

    # Suspicious shell invocation indicators
    for indicator in MALICIOUS_CMD_INDICATORS:
        if indicator in cmd:
            score += 0.35
            break

    # Confidence scaling
    initial_conf = state.get("initial_confidence", 0.8)
    score = (score * 0.5) + (initial_conf * 0.5)
    return min(max(round(score, 2), 0.05), 1.0)


def run_triage(state: DefenseState) -> Dict[str, Any]:
    """
    Executes triage node analysis on the incoming incident alert.
    Returns partial state update with triage_verdict and blast_radius_score.
    """
    path = state.get("target_path", "")
    proc_name = state.get("target_process_name", "")
    cmd = (state.get("command_line") or "").lower()
    conf = state.get("initial_confidence", 0.0)

    # Check 1: Benign developer tooling check
    if is_ide_or_dev_workload(path, proc_name) and not any(ind in cmd for ind in MALICIOUS_CMD_INDICATORS):
        return {
            "triage_verdict": "BENIGN",
            "blast_radius_score": 0.05,
        }

    # Check 2: Severe malicious indicators
    has_malicious_cmd = any(ind in cmd for ind in MALICIOUS_CMD_INDICATORS)
    blast_radius = evaluate_blast_radius(state)

    if has_malicious_cmd or conf >= 0.85:
        verdict = "MALICIOUS"
    elif conf >= 0.60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    return {
        "triage_verdict": verdict,
        "blast_radius_score": blast_radius,
    }
