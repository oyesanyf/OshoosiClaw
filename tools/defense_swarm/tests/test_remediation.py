import pytest
from defense_swarm.agents.remediation import run_remediation, is_safeguarded_target, SAFEGUARD_PROTECTED_PIDS, SAFEGUARD_PROTECTED_NAMES
from defense_swarm.state import DefenseState


def test_immutable_safeguard_pid_immunity():
    for pid in [0, 1, 4]:
        assert is_safeguarded_target(pid, "System") is True
        state: DefenseState = {
            "incident_id": f"INC-PID-{pid}",
            "target_pid": pid,
            "target_process_name": "System",
            "target_path": r"C:\Windows\System32\ntoskrnl.exe",
        }
        res = run_remediation(state)
        steps = res["remediation_steps"]
        assert any(s["action"] == "SAFETY_OVERRIDE_VETO" and s["status"] == "PROTECTED_INVARIANT_PRESERVED" for s in steps)
        assert not any(s["action"] == "TERMINATE_PROCESS" for s in steps)


def test_immutable_safeguard_security_daemons():
    for proc in ["osoosi.exe", "sysmon64.exe", "msmpeng.exe", "sysmon.exe"]:
        assert is_safeguarded_target(9999, proc) is True
        state: DefenseState = {
            "incident_id": f"INC-DAEMON-{proc}",
            "target_pid": 9999,
            "target_process_name": proc,
            "target_path": rf"C:\Program Files\Security\{proc}",
        }
        res = run_remediation(state)
        steps = res["remediation_steps"]
        assert any(s["action"] == "SAFETY_OVERRIDE_VETO" for s in steps)
        assert not any(s["action"] == "TERMINATE_PROCESS" for s in steps)
        assert not any(s["action"] == "QUARANTINE_FILE" for s in steps)


def test_malicious_unprotected_target_remediation():
    state: DefenseState = {
        "incident_id": "INC-MALWARE-1",
        "target_pid": 7890,
        "target_process_name": "ransomware_payload.exe",
        "target_path": r"C:\Users\Public\ransomware_payload.exe",
        "forensic_findings": {
            "sockets": [{"remote_addr": "203.0.113.5:8080", "dns_domain": "bad-c2.net"}]
        },
        "synthesized_yara_rule": "rule test { condition: true }",
    }
    res = run_remediation(state)
    steps = res["remediation_steps"]
    actions = [s["action"] for s in steps]
    assert "TERMINATE_PROCESS" in actions
    assert "BLOCK_NETWORK_REMOTE" in actions
    assert "QUARANTINE_FILE" in actions
    assert "LOAD_DYNAMIC_YARA" in actions
