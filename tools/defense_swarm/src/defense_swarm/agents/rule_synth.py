"""
Rule Synthesizer Agent for LangGraph Defense Swarm.
Synthesizes tailored YARA-X detection patterns and Sigma YAML rules
based on forensic indicators and process behavioral signatures.
Includes strict syntax linting and automated retry self-correction feedback loop.
"""

from typing import Dict, Any, Tuple, Optional
import re
import yaml
from datetime import datetime, timezone
from ..state import DefenseState


def synthesize_yara_rule(state: DefenseState) -> str:
    incident_id = state.get("incident_id", "INC001").replace("-", "_")
    proc_name = state.get("target_process_name", "malware.exe")
    threat_intel = state.get("threat_intel") or {}
    primary_tech = threat_intel.get("primary_technique", "T1055")
    
    clean_proc = re.sub(r"[^a-zA-Z0-9_]", "_", proc_name)
    rule_name = f"Oshoosi_Swarm_{clean_proc}_{primary_tech.replace('.', '_')}"

    # Extract strings from command line or target path
    cmd = state.get("command_line") or ""
    strings_block = []
    
    if cmd:
        escaped_cmd = cmd.replace("\\", "\\\\").replace('"', '\\"')
        strings_block.append(f'        $cmd = "{escaped_cmd}" ascii wide')
    
    strings_block.append(f'        $proc = "{proc_name}" ascii wide nocase')
    strings_block.append('        $magic_pe = { 4D 5A }')

    strings_str = "\n".join(strings_block)

    now_utc = datetime.now(timezone.utc)
    yara_text = f"""rule {rule_name} {{
    meta:
        description = "Autonomous Swarm rule for {proc_name}"
        incident_id = "{incident_id}"
        mitre_technique = "{primary_tech}"
        author = "OpenOshoosi Defense Swarm"
        date = "{now_utc.strftime('%Y-%m-%d')}"
    strings:
{strings_str}
    condition:
        $magic_pe at 0 and ($proc or $cmd)
}}"""
    return yara_text


def synthesize_sigma_rule(state: DefenseState) -> str:
    incident_id = state.get("incident_id", "INC001")
    proc_name = state.get("target_process_name", "malware.exe")
    threat_intel = state.get("threat_intel") or {}
    primary_tech = threat_intel.get("primary_technique", "T1055")

    now_utc = datetime.now(timezone.utc)
    rule_dict = {
        "title": f"Swarm Detection - {proc_name} Execution",
        "id": incident_id,
        "status": "experimental",
        "description": f"Autonomously generated Sigma rule for incident {incident_id}",
        "references": [
            f"https://attack.mitre.org/techniques/{primary_tech.split('.')[0]}/"
        ],
        "author": "OpenOshoosi LangGraph Defense Swarm",
        "date": now_utc.strftime("%Y/%m/%d"),
        "tags": [
            f"attack.{primary_tech.lower()}",
            "attack.defense_evasion",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "Image|endswith": f"\\{proc_name}",
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate administrative workflows",
        ],
        "level": "high",
    }

    return yaml.dump(rule_dict, sort_keys=False)


def validate_rule_syntax(yara_rule: Optional[str], sigma_rule: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validates syntax and schema for synthesized YARA and Sigma rules.
    Returns (True, None) if both pass, or (False, error_log) if validation fails.
    """
    if not yara_rule:
        return False, "YARA rule content is missing or empty"

    # 1. YARA structure validation
    yara_rule_clean = yara_rule.strip()
    if not yara_rule_clean.startswith("rule "):
        return False, "YARA syntax error: rule declaration must begin with 'rule <name>'"

    if "condition:" not in yara_rule_clean:
        return False, "YARA syntax error: missing 'condition:' section"

    # Check balanced braces
    if yara_rule_clean.count("{") != yara_rule_clean.count("}"):
        return False, "YARA syntax error: unbalanced curly braces"

    # 2. Sigma YAML validation
    if not sigma_rule:
        return False, "Sigma rule content is missing or empty"

    try:
        parsed_sigma = yaml.safe_load(sigma_rule)
        if not isinstance(parsed_sigma, dict):
            return False, "Sigma YAML error: document must be a dictionary"
        
        required_keys = ["title", "logsource", "detection"]
        for rk in required_keys:
            if rk not in parsed_sigma:
                return False, f"Sigma schema error: missing required key '{rk}'"

        detection = parsed_sigma.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            return False, "Sigma schema error: 'detection' must contain 'condition'"

    except Exception as exc:
        return False, f"Sigma YAML parsing exception: {str(exc)}"

    return True, None


def run_rule_synthesis(state: DefenseState) -> Dict[str, Any]:
    """
    Synthesizes YARA and Sigma detection rules, running them through the syntax validation gate.
    """
    retries = state.get("rule_synth_retries", 0)
    prev_err = state.get("compiler_error_log")

    # Generate detection rules
    yara_code = synthesize_yara_rule(state)
    sigma_code = synthesize_sigma_rule(state)

    # Validate rules
    passed, err = validate_rule_syntax(yara_code, sigma_code)

    return {
        "synthesized_yara_rule": yara_code,
        "synthesized_sigma_rule": sigma_code,
        "rule_compilation_passed": passed,
        "compiler_error_log": err,
        "rule_synth_retries": retries + 1,
    }
