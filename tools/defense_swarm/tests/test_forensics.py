import pytest
from defense_swarm.agents.forensics import run_forensics, inspect_vad_memory, inspect_mft_artifacts, inspect_active_sockets
from defense_swarm.state import DefenseState


def test_forensics_vad_unbacked_memory():
    vad = inspect_vad_memory(4444, "hollowing_decoy.exe")
    assert vad["anomaly_detected"] is True
    assert len(vad["unbacked_rwx_regions"]) == 1
    region = vad["unbacked_rwx_regions"][0]
    assert region["protection"] == "PAGE_EXECUTE_READWRITE"
    assert region["mapped_file"] is None
    assert region["entropy"] > 7.0


def test_forensics_run_forensics_aggregation():
    state: DefenseState = {
        "incident_id": "INC-FOR-1",
        "target_pid": 4444,
        "target_process_name": "hollowing_decoy.exe",
        "target_path": r"C:\Temp\decoy.exe",
    }
    res = run_forensics(state)
    findings = res["forensic_findings"]
    assert findings["total_anomalies"] >= 2
    assert findings["vad"]["anomaly_detected"] is True
    assert len(findings["sockets"]) > 0
