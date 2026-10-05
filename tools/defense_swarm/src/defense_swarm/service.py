"""
FastAPI Service for OpenỌ̀ṣọ́ọ̀sì LangGraph Autonomous Defense Swarm.
Provides webhook endpoints for Fast-Ring EDR trigger, real-time status queries,
and Human-in-the-Loop approval/resume lifecycle.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, status
from langgraph.types import Command
from langgraph.checkpoint.memory import MemorySaver

from .models import (
    IncidentAlertRequest,
    ApprovalRequest,
    HealthResponse,
    IncidentStatusResponse,
)
from .state import DefenseState
from .graph import build_defense_swarm_graph

app = FastAPI(
    title="OpenOshoosi Defense Swarm Service",
    description="LangGraph Autonomous Multi-Agent Ring-1 Deep Defense Swarm",
    version="0.1.0",
)

_checkpointer = MemorySaver()
_swarm_graph = None


def get_graph():
    global _swarm_graph, _checkpointer
    if _swarm_graph is None:
        _swarm_graph = build_defense_swarm_graph(checkpointer=_checkpointer)
    return _swarm_graph


incidents_db: Dict[str, Dict[str, Any]] = {}


def _extract_response_status(graph_state: Any, final_state: Dict[str, Any]) -> str:
    if graph_state and getattr(graph_state, "next", None):
        if "human_review_node" in graph_state.next:
            return "WAITING_APPROVAL"
        return "RUNNING"

    verdict = final_state.get("triage_verdict")
    approval = final_state.get("operator_approval_status")

    if verdict == "BENIGN":
        return "DE_ESCALATED"
    if approval == "REJECTED":
        return "REJECTED"
    return "COMPLETED"


def _state_to_response(incident_id: str, st: Dict[str, Any], current_status: str) -> IncidentStatusResponse:
    return IncidentStatusResponse(
        incident_id=incident_id,
        status=current_status,
        triage_verdict=st.get("triage_verdict"),
        blast_radius_score=st.get("blast_radius_score"),
        current_node=None,
        forensic_findings=st.get("forensic_findings"),
        threat_intel=st.get("threat_intel"),
        synthesized_yara_rule=st.get("synthesized_yara_rule"),
        synthesized_sigma_rule=st.get("synthesized_sigma_rule"),
        rule_compilation_passed=st.get("rule_compilation_passed"),
        remediation_steps=st.get("remediation_steps"),
        operator_approval_status=st.get("operator_approval_status"),
        execution_results=st.get("execution_results"),
        mesh_broadcast_status=st.get("mesh_broadcast_status"),
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        version="0.1.0",
        active_incidents=len(incidents_db),
        engine="LangGraph StateGraph",
    )


@app.post("/api/swarm/investigate", response_model=IncidentStatusResponse)
@app.post("/api/swarm/incident", response_model=IncidentStatusResponse)
async def trigger_investigation(req: IncidentAlertRequest):
    incident_id = req.incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"
    thread_config = {"configurable": {"thread_id": incident_id}}
    graph = get_graph()

    initial_state: DefenseState = {
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_pid": req.target_pid,
        "target_process_name": req.target_process_name or "unknown.exe",
        "target_path": req.target_path or "",
        "command_line": req.command_line or "",
        "parent_pid": req.parent_pid or 0,
        "parent_process_name": req.parent_process_name or "unknown.exe",
        "initial_detection_engine": req.initial_detection_engine or "core",
        "initial_confidence": req.initial_confidence,
        "rule_synth_retries": 0,
    }

    try:
        graph.invoke(initial_state, config=thread_config)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Swarm graph invocation error: {str(exc)}",
        )

    current_snapshot = graph.get_state(thread_config)
    state_values = current_snapshot.values if current_snapshot else initial_state
    incident_status = _extract_response_status(current_snapshot, state_values)

    incidents_db[incident_id] = {
        "incident_id": incident_id,
        "status": incident_status,
        "created_at": initial_state["timestamp"],
        "target_pid": req.target_pid,
        "target_process_name": req.target_process_name,
        "state": state_values,
    }

    return _state_to_response(incident_id, state_values, incident_status)


@app.get("/api/swarm/status/{incident_id}", response_model=IncidentStatusResponse)
async def get_incident_status(incident_id: str):
    thread_config = {"configurable": {"thread_id": incident_id}}
    graph = get_graph()
    snapshot = graph.get_state(thread_config)

    if not snapshot or not snapshot.values:
        if incident_id in incidents_db:
            rec = incidents_db[incident_id]
            return _state_to_response(incident_id, rec.get("state", {}), rec.get("status", "UNKNOWN"))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found")

    state_values = snapshot.values
    incident_status = _extract_response_status(snapshot, state_values)
    return _state_to_response(incident_id, state_values, incident_status)


@app.get("/api/swarm/approvals", response_model=List[IncidentStatusResponse])
@app.get("/api/approvals", response_model=List[IncidentStatusResponse])
async def list_pending_approvals():
    pending = []
    graph = get_graph()
    for inc_id, data in incidents_db.items():
        thread_config = {"configurable": {"thread_id": inc_id}}
        snapshot = graph.get_state(thread_config)
        if snapshot and snapshot.next and "human_review_node" in snapshot.next:
            pending.append(_state_to_response(inc_id, snapshot.values, "WAITING_APPROVAL"))
        elif data.get("status") == "WAITING_APPROVAL":
            pending.append(_state_to_response(inc_id, data.get("state", {}), "WAITING_APPROVAL"))
    return pending


@app.post("/api/swarm/resume", response_model=IncidentStatusResponse)
async def resume_investigation(incident_id: str, req: ApprovalRequest):
    thread_config = {"configurable": {"thread_id": incident_id}}
    graph = get_graph()
    snapshot = graph.get_state(thread_config)

    if not snapshot or not snapshot.values:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found or has no active state",
        )

    if not snapshot.next or "human_review_node" not in snapshot.next:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incident {incident_id} is not waiting for approval (current next: {snapshot.next})",
        )

    resume_payload = {
        "decision": req.decision.upper(),
        "operator_feedback": req.operator_feedback,
    }

    try:
        graph.invoke(Command(resume=resume_payload), config=thread_config)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to resume swarm graph: {str(exc)}",
        )

    final_snapshot = graph.get_state(thread_config)
    state_values = final_snapshot.values if final_snapshot else snapshot.values
    new_status = _extract_response_status(final_snapshot, state_values)

    if incident_id in incidents_db:
        incidents_db[incident_id]["status"] = new_status
        incidents_db[incident_id]["state"] = state_values

    return _state_to_response(incident_id, state_values, new_status)


@app.post("/api/swarm/approve/{incident_id}", response_model=IncidentStatusResponse)
async def approve_incident(incident_id: str, feedback: Optional[str] = None):
    req = ApprovalRequest(decision="APPROVED", operator_feedback=feedback or "Approved by operator")
    return await resume_investigation(incident_id, req)


@app.post("/api/swarm/reject/{incident_id}", response_model=IncidentStatusResponse)
async def reject_incident(incident_id: str, feedback: Optional[str] = None):
    req = ApprovalRequest(decision="REJECTED", operator_feedback=feedback or "Rejected by operator")
    return await resume_investigation(incident_id, req)


@app.get("/api/swarm/incidents", response_model=List[IncidentStatusResponse])
async def list_all_incidents():
    result = []
    graph = get_graph()
    for inc_id, data in incidents_db.items():
        thread_config = {"configurable": {"thread_id": inc_id}}
        snapshot = graph.get_state(thread_config)
        state_values = snapshot.values if snapshot and snapshot.values else data.get("state", {})
        st = _extract_response_status(snapshot, state_values) if snapshot else data.get("status", "UNKNOWN")
        result.append(_state_to_response(inc_id, state_values, st))
    return result
