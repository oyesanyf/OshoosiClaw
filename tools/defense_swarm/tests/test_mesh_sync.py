import pytest
from defense_swarm.agents.mesh_sync import run_mesh_sync, generate_skill_markdown
from defense_swarm.state import DefenseState


def test_mesh_sync_gossipsub_payload_generation():
    state: DefenseState = {
        "incident_id": "INC-MESH-1",
        "target_pid": 1122,
        "target_process_name": "mimikatz.exe",
        "synthesized_yara_rule": "rule Swarm_Mimikatz { condition: true }",
        "threat_intel": {"primary_technique": "T1003.001"},
    }
    res = run_mesh_sync(state)
    status = res["mesh_broadcast_status"]
    assert status["gossipsub_yara_queued"] is True
    assert status["yara_payload"]["topic"] == "osoosi-yara-v1"
    assert status["skills_payload"]["topic"] == "osoosi-skills-v1"
    assert "T1003.001" in status["skills_payload"]["markdown_content"]
