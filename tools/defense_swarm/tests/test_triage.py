import pytest
from defense_swarm.agents.triage import run_triage, is_ide_or_dev_workload, evaluate_blast_radius
from defense_swarm.state import DefenseState


def test_triage_developer_cargo_build_benign():
    state: DefenseState = {
        "incident_id": "INC-DEV-1",
        "target_pid": 12840,
        "target_process_name": "cargo.exe",
        "target_path": r"C:\Users\dev\.cargo\bin\cargo.exe",
        "command_line": "cargo build --release",
        "initial_confidence": 0.50,
    }
    result = run_triage(state)
    assert result["triage_verdict"] == "BENIGN"
    assert result["blast_radius_score"] <= 0.10


def test_triage_malicious_mimikatz():
    state: DefenseState = {
        "incident_id": "INC-ATTACK-1",
        "target_pid": 4820,
        "target_process_name": "mimikatz.exe",
        "target_path": r"C:\Temp\mimikatz.exe",
        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "initial_confidence": 0.95,
    }
    result = run_triage(state)
    assert result["triage_verdict"] == "MALICIOUS"
    assert result["blast_radius_score"] >= 0.70


def test_triage_vssadmin_ransomware_blast_radius():
    state: DefenseState = {
        "incident_id": "INC-ATTACK-2",
        "target_pid": 512,
        "target_process_name": "vssadmin.exe",
        "target_path": r"C:\Windows\System32\vssadmin.exe",
        "command_line": "vssadmin delete shadows /all /quiet",
        "initial_confidence": 0.90,
    }
    score = evaluate_blast_radius(state)
    assert score >= 0.75
