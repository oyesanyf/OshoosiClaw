"""
FastAPI REST Service for OpenỌ̀ṣọ́ọ̀sì LangGraph Autonomous Defense Swarm.
Exposes endpoints for Rust core EDR webhook ingestion,
status queries, operator human-in-the-loop approvals, and health checks.
"""

from typing import Dict, Any, Optional
import uuid
from datetime import datetime, timezone
import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from langgraph.types import Command
from langgraph.checkpoint.memory import MemorySaver

from .state import DefenseState
from .models import (
    IncidentAlertRequest,
    IncidentStatusResponse,
    ApprovalRequest,
    HealthResponse,
)
from .graph import build_defense_swarm_graph

app = FastAPI(
    title="OpenỌ̀ṣọ́ọ̀sì Autonomous Defense Swarm",
    description="LangGraph Multi-Agent Pipeline for post-containment deep forensics, rule synthesis, and fleet immunization",
    version="0.1.0",
)

# Shared in-memory checkpointer & compiled StateGraph
checkpointer = MemorySaver()
swarm_graph = build_defense_swarm_graph(checkpointer=checkpointer)

# In-memory store for tracking active incidents
ACTIVE_INCIDENTS: Dict[str, Dict[str, Any]] = {}


async def _run_graph_async(thread_id: str, initial_state: DefenseState):
    """Executes the StateGraph asynchronously in background."""
    config = {"configurable": {"thread_id": thread_id}}
    try:
        ACTIVE_INCIDENTS[thread_id]["status"] = "RUNNING"
        # Run graph
        result = await asyncio.to_thread(swarm_graph.invoke, initial_state, config=config)
        
        # Check current snapshot state to see if interrupted
        state_snapshot = swarm_graph.get_state(config)
        if state_snapshot.next:
            ACTIVE_INCIDENTS[thread_id]["status"] = "WAITING_APPROVAL"
            ACTIVE_INCIDENTS[thread_id]["current_node"] = state_snapshot.next[0]
        else:
            verdict = result.get("triage_verdict", "MALICIOUS")
            if verdict == "BENIGN":
                ACTIVE_INCIDENTS[thread_id]["status"] = "DE_ESCALATED"
            else:
                approval = result.get("operator_approval_status", "COMPLETED")
                ACTIVE_INCIDENTS[thread_id]["status"] = "REJECTED" if approval == "REJECTED" else "COMPLETED"
            ACTIVE_INCIDENTS[thread_id]["current_node"] = "END"

        ACTIVE_INCIDENTS[thread_id]["state"] = result
    except Exception as exc:
        ACTIVE_INCIDENTS[thread_id]["status"] = "ERROR"
        ACTIVE_INCIDENTS[thread_id]["error"] = str(exc)


@app.get("/api/swarm/health", response_model=HealthResponse)
async def get_health():
    """Returns service health, engine details, and active incident count."""
    return HealthResponse(
        status="ok",
        version="0.1.0",
        active_incidents=len(ACTIVE_INCIDENTS),
        engine="LangGraph StateGraph",
    )


@app.post("/api/swarm/investigate")
async def trigger_investigation(
    req: IncidentAlertRequest,
    background_tasks: BackgroundTasks,
):
    """
    Ingests security incident alert from Rust core EDR or CLI and initiates
    asynchronous LangGraph multi-agent defense workflow.
    """
    incident_id = req.incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"

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
        "triage_verdict": "SUSPICIOUS",
        "blast_radius_score": 0.5,
        "forensic_findings": {},
        "threat_intel": {},
        "synthesized_yara_rule": None,
        "synthesized_sigma_rule": None,
        "rule_compilation_passed": False,
        "compiler_error_log": None,
        "rule_synth_retries": 0,
        "remediation_steps": [],
        "operator_approval_status": "PENDING",
        "operator_feedback": None,
        "execution_results": [],
        "mesh_broadcast_status": {},
    }

    ACTIVE_INCIDENTS[incident_id] = {
        "status": "QUEUED",
        "initial_request": req.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "current_node": "triage_node",
        "state": initial_state,
    }

    background_tasks.add_task(_run_graph_async, incident_id, initial_state)

    return {
        "incident_id": incident_id,
        "status": "INVESTIGATION_STARTED",
        "target_pid": req.target_pid,
        "target_process": req.target_process_name,
    }


@app.get("/api/swarm/status/{incident_id}", response_model=IncidentStatusResponse)
async def get_incident_status(incident_id: str):
    """
    Retrieves full execution state, current node, forensic findings,
    synthesized rules, and remediation status for a specific incident.
    """
    if incident_id not in ACTIVE_INCIDENTS:
        # Check if exists in checkpointer
        config = {"configurable": {"thread_id": incident_id}}
        state_snapshot = swarm_graph.get_state(config)
        if not state_snapshot.values:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
        vals = state_snapshot.values
        status = "WAITING_APPROVAL" if state_snapshot.next else "COMPLETED"
        node = state_snapshot.next[0] if state_snapshot.next else "END"
    else:
        record = ACTIVE_INCIDENTS[incident_id]
        vals = record.get("state", {})
        status = record.get("status", "UNKNOWN")
        node = record.get("current_node", "UNKNOWN")

    return IncidentStatusResponse(
        incident_id=incident_id,
        status=status,
        triage_verdict=vals.get("triage_verdict"),
        blast_radius_score=vals.get("blast_radius_score"),
        current_node=node,
        forensic_findings=vals.get("forensic_findings"),
        threat_intel=vals.get("threat_intel"),
        synthesized_yara_rule=vals.get("synthesized_yara_rule"),
        synthesized_sigma_rule=vals.get("synthesized_sigma_rule"),
        rule_compilation_passed=vals.get("rule_compilation_passed"),
        remediation_steps=vals.get("remediation_steps"),
        operator_approval_status=vals.get("operator_approval_status"),
        execution_results=vals.get("execution_results"),
        mesh_broadcast_status=vals.get("mesh_broadcast_status"),
    )


@app.post("/api/swarm/approve/{incident_id}")
async def approve_incident(incident_id: str, req: ApprovalRequest):
    """
    Resumes graph execution paused at the human_review_node checkpoint
    with the operator's decision ('APPROVED' or 'REJECTED') and optional feedback.
    """
    config = {"configurable": {"thread_id": incident_id}}
    state_snapshot = swarm_graph.get_state(config)

    if not state_snapshot.values:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found in graph state")

    # Resume graph execution using LangGraph Command
    resume_payload = {
        "decision": req.decision.upper(),
        "operator_feedback": req.operator_feedback,
    }

    try:
        result = await asyncio.to_thread(
            swarm_graph.invoke,
            Command(resume=resume_payload),
            config=config,
        )

        final_status = "REJECTED" if req.decision.upper() == "REJECTED" else "COMPLETED"
        if incident_id in ACTIVE_INCIDENTS:
            ACTIVE_INCIDENTS[incident_id]["status"] = final_status
            ACTIVE_INCIDENTS[incident_id]["current_node"] = "END"
            ACTIVE_INCIDENTS[incident_id]["state"] = result

        return {
            "incident_id": incident_id,
            "status": final_status,
            "decision": req.decision.upper(),
            "execution_results": result.get("execution_results", []),
            "mesh_broadcast_status": result.get("mesh_broadcast_status", {}),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to resume graph: {str(exc)}")
