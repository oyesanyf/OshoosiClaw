import pytest
from langgraph.types import Command
from defense_swarm.graph import build_defense_swarm_graph
from defense_swarm.state import DefenseState


def test_graph_benign_developer_execution():
    graph = build_defense_swarm_graph()
    thread_cfg = {"configurable": {"thread_id": "test-dev-run"}}
    initial_state: DefenseState = {
        "incident_id": "INC-DEV-RUN",
        "target_pid": 8800,
        "target_process_name": "cargo.exe",
        "target_path": r"C:\Users\dev\.cargo\bin\cargo.exe",
        "command_line": "cargo test --all",
        "initial_confidence": 0.30,
    }
    result = graph.invoke(initial_state, config=thread_cfg)
    assert result["triage_verdict"] == "BENIGN"
    assert result["operator_approval_status"] == "AUTO_APPROVED"
    assert any(r["action"] == "UNFREEZE_PROCESS" for r in result["execution_results"])


def test_graph_malicious_interrupt_and_resume_approved():
    graph = build_defense_swarm_graph()
    thread_cfg = {"configurable": {"thread_id": "test-attack-interrupt"}}
    initial_state: DefenseState = {
        "incident_id": "INC-ATTACK-INTERRUPT",
        "target_pid": 9999,
        "target_process_name": "badware.exe",
        "target_path": r"C:\Temp\badware.exe",
        "command_line": "badware.exe -enc AAAAAA",
        "initial_confidence": 0.95,
        "rule_synth_retries": 0,
    }

    # First invoke will pause at human_review_node due to blast radius >= 0.70
    graph.invoke(initial_state, config=thread_cfg)
    snapshot = graph.get_state(thread_cfg)
    assert "human_review_node" in snapshot.next

    # Resume with approval
    resumed_result = graph.invoke(
        Command(resume={"decision": "APPROVED", "operator_feedback": "Proceed with containment"}),
        config=thread_cfg,
    )
    assert resumed_result["operator_approval_status"] == "APPROVED"
    assert len(resumed_result["execution_results"]) > 0
    assert resumed_result["mesh_broadcast_status"]["gossipsub_yara_queued"] is True


def test_graph_malicious_interrupt_and_resume_rejected():
    graph = build_defense_swarm_graph()
    thread_cfg = {"configurable": {"thread_id": "test-attack-rejected"}}
    initial_state: DefenseState = {
        "incident_id": "INC-ATTACK-REJECTED",
        "target_pid": 7777,
        "target_process_name": "unknown_tool.exe",
        "command_line": "unknown_tool.exe -enc QWERTY",
        "initial_confidence": 0.90,
        "rule_synth_retries": 0,
    }

    graph.invoke(initial_state, config=thread_cfg)
    snapshot = graph.get_state(thread_cfg)
    assert "human_review_node" in snapshot.next

    # Resume with rejection
    resumed_result = graph.invoke(
        Command(resume={"decision": "REJECTED", "operator_feedback": "False alarm; internal testing"}),
        config=thread_cfg,
    )
    assert resumed_result["operator_approval_status"] == "REJECTED"
    assert any(r["action"] == "EXECUTION_ABORTED" for r in resumed_result["execution_results"])
