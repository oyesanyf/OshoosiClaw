"""
Remediation Planner Agent for LangGraph Defense Swarm.
Formulates surgical, prioritized containment and rollback operations
while strictly enforcing immutable safeguards for Windows kernel and EDR processes.
"""

from typing import Dict, Any, List
from ..state import DefenseState

SAFEGUARD_PROTECTED_PIDS = {0, 1, 4}

SAFEGUARD_PROTECTED_NAMES = {
    "osoosi.exe",
    "sysmon64.exe",
    "sysmon.exe",
    "sysmon64a.exe",
    "msmpeng.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "dwm.exe",
}


def is_safeguarded_target(pid: int, process_name: str) -> bool:
    if pid in SAFEGUARD_PROTECTED_PIDS:
        return True
    
    clean_name = (process_name or "").lower().strip()
    if clean_name in SAFEGUARD_PROTECTED_NAMES:
        return True

    return False


def run_remediation(state: DefenseState) -> Dict[str, Any]:
    """
    Formulates remediation plan with zero-trust safeguards.
    """
    target_pid = state.get("target_pid", 0)
    target_name = state.get("target_process_name", "unknown.exe")
    target_path = state.get("target_path", "")
    forensic = state.get("forensic_findings") or {}
    sockets = forensic.get("sockets") or []

    steps: List[Dict[str, Any]] = []

    # Step 1: Process action (with strict safeguard check)
    if is_safeguarded_target(target_pid, target_name):
        steps.append({
            "action": "SAFETY_OVERRIDE_VETO",
            "target": f"PID {target_pid} ({target_name})",
            "reason": "Process is a protected system kernel/EDR entity (PID 0,1,4 or critical infrastructure). Termination forbidden.",
            "status": "PROTECTED_INVARIANT_PRESERVED",
        })
    else:
        steps.append({
            "action": "TERMINATE_PROCESS",
            "target": f"PID {target_pid} ({target_name})",
            "reason": "Neutralize active malicious execution thread.",
            "status": "PLANNED",
        })

    # Step 2: Active C2 socket termination
    if sockets:
        for s in sockets:
            remote = s.get("remote_addr")
            if remote:
                steps.append({
                    "action": "BLOCK_NETWORK_REMOTE",
                    "target": remote,
                    "reason": f"Sever communication to adversary C2 ({s.get('dns_domain', 'unknown')})",
                    "status": "PLANNED",
                })

    # Step 3: Binary Quarantine
    if target_path and not is_safeguarded_target(target_pid, target_name):
        steps.append({
            "action": "QUARANTINE_FILE",
            "target": target_path,
            "reason": "Prevent re-launch from persistent disk location.",
            "status": "PLANNED",
        })

    # Step 4: YARA-X Dynamic Rule Deployment
    if state.get("synthesized_yara_rule"):
        steps.append({
            "action": "LOAD_DYNAMIC_YARA",
            "target": "PolicyEngine::live_rules",
            "reason": "Hot-reload synthesized YARA pattern to immediately detect lateral movement.",
            "status": "PLANNED",
        })

    return {"remediation_steps": steps}
