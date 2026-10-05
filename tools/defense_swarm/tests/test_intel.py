import pytest
from defense_swarm.agents.intel import run_intel, correlate_mitre_techniques
from defense_swarm.state import DefenseState


def test_intel_mitre_injection_correlation():
    state: DefenseState = {
        "incident_id": "INC-INTEL-1",
        "target_pid": 1920,
        "target_process_name": "inject_host.exe",
        "command_line": "inject_host.exe --target 400",
        "forensic_findings": {
            "vad": {"anomaly_detected": True}
        }
    }
    techniques = correlate_mitre_techniques(state)
    assert any(t["id"] == "T1055.012" for t in techniques)


def test_intel_cve_correlation():
    state: DefenseState = {
        "incident_id": "INC-INTEL-2",
        "target_pid": 2048,
        "target_process_name": "curl.exe",
        "command_line": "curl.exe http://victim/login -H 'X-Exploit: CVE-2023-34362'",
    }
    res = run_intel(state)
    intel = res["threat_intel"]
    assert len(intel["cve_correlations"]) == 1
    cve = intel["cve_correlations"][0]
    assert cve["cve_id"] == "CVE-2023-34362"
    assert cve["cisa_kev"] is True
    assert cve["ransomware_association"] == "Cl0p"
