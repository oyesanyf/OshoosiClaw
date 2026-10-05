"""
LangGraph StateGraph assembly for OpenỌ̀ṣọ́ọ̀sì Autonomous Defense Swarm.
Orchestrates multi-agent analysis, cyclic rule self-correction,
Human-in-the-Loop checkpointing via interrupt(), and fleet immunization.
"""

from typing import Dict, Any, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import interrupt

from .state import DefenseState
from .agents import (
    run_triage,
    run_forensics,
    run_intel,
    run_rule_synthesis,
    run_remediation,
    run_mesh_sync,
)


def triage_node(state: DefenseState) -> Dict[str, Any]:
    return run_triage(state)


def de_escalate_node(state: DefenseState) -> Dict[str, Any]:
    return {
        "triage_verdict": "BENIGN",
        "operator_approval_status": "AUTO_APPROVED",
        "execution_results": [
            {
                "action": "UNFREEZE_PROCESS",
                "target": f"PID {state.get('target_pid')}",
                "status": "CLEARED",
                "reason": "Evaluated as benign developer activity or false positive alert.",
            }
        ],
    }


def forensics_node(state: DefenseState) -> Dict[str, Any]:
    return run_forensics(state)


def intel_node(state: DefenseState) -> Dict[str, Any]:
    return run_intel(state)


def rule_synth_node(state: DefenseState) -> Dict[str, Any]:
    return run_rule_synthesis(state)


def remediation_node(state: DefenseState) -> Dict[str, Any]:
    return run_remediation(state)


def human_review_node(state: DefenseState) -> Dict[str, Any]:
    """
    Checkpoint gate using LangGraph interrupt().
    Pauses execution for operator approval if not already approved or rejected.
    """
    approval = state.get("operator_approval_status")
    if approval in ("APPROVED", "AUTO_APPROVED", "REJECTED"):
        return {}

    # LangGraph interrupt snapshots state to checkpointer and pauses
    review_prompt = {
        "incident_id": state.get("incident_id"),
        "target_pid": state.get("target_pid"),
        "target_process": state.get("target_process_name"),
        "blast_radius_score": state.get("blast_radius_score"),
        "remediation_steps": state.get("remediation_steps"),
        "prompt": "Operator approval required for elevated blast radius remediation.",
    }

    operator_decision = interrupt(review_prompt)

    # When resumed, operator_decision contains the resume payload dict
    if isinstance(operator_decision, dict):
        status = operator_decision.get("decision", "APPROVED").upper()
        feedback = operator_decision.get("operator_feedback")
    elif isinstance(operator_decision, str):
        status = operator_decision.upper()
        feedback = None
    else:
        status = "APPROVED"
        feedback = None

    return {
        "operator_approval_status": status,
        "operator_feedback": feedback,
    }


def executor_node(state: DefenseState) -> Dict[str, Any]:
    """
    Executes or simulates the planned remediation steps.
    """
    approval = state.get("operator_approval_status", "AUTO_APPROVED")
    steps = state.get("remediation_steps", [])
    results = []

    if approval == "REJECTED":
        results.append({
            "action": "EXECUTION_ABORTED",
            "status": "REJECTED_BY_OPERATOR",
            "feedback": state.get("operator_feedback", "Operator denied remediation plan."),
        })
        return {"execution_results": results}

    for step in steps:
        results.append({
            "action": step.get("action"),
            "target": step.get("target"),
            "status": "SUCCESS" if step.get("status") != "PROTECTED_INVARIANT_PRESERVED" else "PRESERVED",
            "reason": step.get("reason"),
        })

    return {"execution_results": results}


def mesh_sync_node(state: DefenseState) -> Dict[str, Any]:
    return run_mesh_sync(state)


# --- Routing Conditions ---

def check_triage(state: DefenseState) -> str:
    verdict = state.get("triage_verdict", "MALICIOUS")
    if verdict == "BENIGN":
        return "de_escalate"
    return "forensics"


def validate_rule_condition(state: DefenseState) -> str:
    passed = state.get("rule_compilation_passed", False)
    retries = state.get("rule_synth_retries", 0)

    # Self-correcting loop: up to 3 retries
    if not passed and retries < 3:
        return "retry_synth"
    return "remediation"


def check_approval_requirement(state: DefenseState) -> str:
    blast_radius = state.get("blast_radius_score", 0.0)
    current_status = state.get("operator_approval_status")

    if current_status in ("APPROVED", "AUTO_APPROVED"):
        return "executor"
    if current_status == "REJECTED":
        return "human_review"

    # High blast radius (>= 0.70) requires operator sign-off
    if blast_radius >= 0.70:
        return "human_review"

    return "executor"


def check_executor_route(state: DefenseState) -> str:
    approval = state.get("operator_approval_status", "")
    if approval == "REJECTED":
        return "end"
    return "mesh_sync"


def build_defense_swarm_graph(checkpointer: Optional[Any] = None) -> Any:
    """
    Assembles and compiles the LangGraph StateGraph.
    """
    workflow = StateGraph(DefenseState)

    # Add Nodes
    workflow.add_node("triage_node", triage_node)
    workflow.add_node("de_escalate_node", de_escalate_node)
    workflow.add_node("forensics_node", forensics_node)
    workflow.add_node("intel_node", intel_node)
    workflow.add_node("rule_synth_node", rule_synth_node)
    workflow.add_node("remediation_node", remediation_node)
    workflow.add_node("human_review_node", human_review_node)
    workflow.add_node("executor_node", executor_node)
    workflow.add_node("mesh_sync_node", mesh_sync_node)

    # Entry point
    workflow.add_edge(START, "triage_node")

    # Conditional Branch: Triage
    workflow.add_conditional_edges(
        "triage_node",
        check_triage,
        {
            "de_escalate": "de_escalate_node",
            "forensics": "forensics_node",
        },
    )

    workflow.add_edge("de_escalate_node", END)
    workflow.add_edge("forensics_node", "intel_node")
    workflow.add_edge("intel_node", "rule_synth_node")

    # Conditional Branch: Rule validation self-correction loop
    workflow.add_conditional_edges(
        "rule_synth_node",
        validate_rule_condition,
        {
            "retry_synth": "rule_synth_node",
            "remediation": "remediation_node",
        },
    )

    # Conditional Branch: Human Approval vs Auto-Approval
    workflow.add_conditional_edges(
        "remediation_node",
        check_approval_requirement,
        {
            "human_review": "human_review_node",
            "executor": "executor_node",
        },
    )

    workflow.add_edge("human_review_node", "executor_node")

    workflow.add_conditional_edges(
        "executor_node",
        check_executor_route,
        {
            "mesh_sync": "mesh_sync_node",
            "end": END,
        },
    )
    workflow.add_edge("mesh_sync_node", END)

    if checkpointer is None:
        checkpointer = MemorySaver()

    return workflow.compile(checkpointer=checkpointer)
