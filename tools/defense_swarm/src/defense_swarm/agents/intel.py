"""
Threat Intelligence Correlator Agent for LangGraph Defense Swarm.
Correlates forensic evidence and process behavior against MITRE ATT&CK matrix,
CISA Known Exploited Vulnerabilities (KEV), and CVSS vulnerability registries.
"""

from typing import Dict, Any, List
from ..state import DefenseState

# Built-in reference mappings for MITRE ATT&CK techniques
MITRE_TACTIC_TECHNIQUE_MAP = {
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "sub_techniques": ["T1055.012 - Process Hollowing", "T1055.001 - Dynamic-link Library Injection"],
        "severity": "HIGH",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "sub_techniques": [],
        "severity": "CRITICAL",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "sub_techniques": ["T1003.001 - LSASS Memory"],
        "severity": "CRITICAL",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "sub_techniques": ["T1059.001 - PowerShell"],
        "severity": "MEDIUM",
    },
}

KNOWN_KEV_ENTRIES = {
    "CVE-2023-34362": {"product": "MOVEit Transfer", "cvss": 9.8, "in_kev": True, "ransomware_campaign": "Cl0p"},
    "CVE-2024-21413": {"product": "Microsoft Outlook", "cvss": 9.8, "in_kev": True, "ransomware_campaign": "Unknown"},
    "CVE-2023-27350": {"product": "PaperCut MF/NG", "cvss": 9.8, "in_kev": True, "ransomware_campaign": "LockBit 3.0"},
}


def correlate_mitre_techniques(state: DefenseState) -> List[Dict[str, Any]]:
    cmd = (state.get("command_line") or "").lower()
    proc = (state.get("target_process_name") or "").lower()
    forensics = state.get("forensic_findings") or {}
    vad = forensics.get("vad") or {}

    matched: List[Dict[str, Any]] = []

    # Check for Process Injection
    if vad.get("anomaly_detected") or "hollow" in proc or "inject" in cmd:
        entry = MITRE_TACTIC_TECHNIQUE_MAP["T1055"]
        matched.append({
            "id": "T1055.012",
            "name": entry["name"],
            "tactic": entry["tactic"],
            "severity": entry["severity"],
        })

    # Check for Ransomware encryption
    if "encrypt" in cmd or "decoy_ransomware" in proc or "vssadmin" in cmd:
        entry = MITRE_TACTIC_TECHNIQUE_MAP["T1486"]
        matched.append({
            "id": "T1486",
            "name": entry["name"],
            "tactic": entry["tactic"],
            "severity": entry["severity"],
        })

    # Check for PowerShell abuse
    if "powershell" in cmd or "-enc" in cmd:
        entry = MITRE_TACTIC_TECHNIQUE_MAP["T1059"]
        matched.append({
            "id": "T1059.001",
            "name": entry["name"],
            "tactic": entry["tactic"],
            "severity": entry["severity"],
        })

    # Fallback to T1055 if none identified
    if not matched:
        matched.append({
            "id": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion",
            "severity": "HIGH",
        })

    return matched


def run_intel(state: DefenseState) -> Dict[str, Any]:
    """
    Correlates incident forensic state with MITRE ATT&CK and vulnerability databases.
    """
    mitre_matches = correlate_mitre_techniques(state)

    # Check if command line mentions any specific CVE
    cmd = (state.get("command_line") or "").upper()
    cve_findings = []
    for cve_id, meta in KNOWN_KEV_ENTRIES.items():
        if cve_id in cmd:
            cve_findings.append({
                "cve_id": cve_id,
                "product": meta["product"],
                "cvss": meta["cvss"],
                "cisa_kev": meta["in_kev"],
                "ransomware_association": meta["ransomware_campaign"],
            })

    threat_intel = {
        "mitre_techniques": mitre_matches,
        "primary_technique": mitre_matches[0]["id"] if mitre_matches else "T1055",
        "cve_correlations": cve_findings,
        "threat_severity": "CRITICAL" if any(m.get("severity") == "CRITICAL" for m in mitre_matches) else "HIGH",
        "confidence_boost": 0.05 if mitre_matches else 0.0,
    }

    return {"threat_intel": threat_intel}
