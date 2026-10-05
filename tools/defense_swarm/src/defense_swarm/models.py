from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class IncidentAlertRequest(BaseModel):
    """Payload received from Rust core EDR or CLI to trigger investigation."""
    incident_id: Optional[str] = None
    target_pid: int = Field(default=0, description="Target process ID")
    target_process_name: Optional[str] = Field(default="unknown.exe", description="Process executable basename")
    target_path: Optional[str] = Field(default="", description="Full executable file path")
    command_line: Optional[str] = Field(default="", description="Process command line arguments")
    parent_pid: Optional[int] = Field(default=0, description="Parent process ID")
    parent_process_name: Optional[str] = Field(default="unknown.exe", description="Parent process name")
    initial_detection_engine: Optional[str] = Field(default="core", description="Triggering detection engine")
    initial_confidence: float = Field(default=0.90, description="Initial threat confidence score (0.0 - 1.0)")
    mitre_technique: Optional[str] = Field(default=None, description="Identified MITRE ATT&CK technique")
    tags: Optional[List[str]] = Field(default_factory=list, description="Additional alert metadata tags")


class ApprovalRequest(BaseModel):
    """Operator decision to approve or reject paused remediation plan."""
    decision: str = Field(..., description="'APPROVED' or 'REJECTED'")
    operator_feedback: Optional[str] = Field(default=None, description="Analyst review comments or override notes")


class HealthResponse(BaseModel):
    """Service status and capability metadata."""
    status: str = "ok"
    version: str = "0.1.0"
    active_incidents: int = 0
    engine: str = "LangGraph StateGraph"


class IncidentStatusResponse(BaseModel):
    """Full snapshot of the incident state within the LangGraph lifecycle."""
    incident_id: str
    status: str  # "RUNNING", "WAITING_APPROVAL", "COMPLETED", "DE_ESCALATED", "REJECTED"
    triage_verdict: Optional[str] = None
    blast_radius_score: Optional[float] = None
    current_node: Optional[str] = None
    forensic_findings: Optional[Dict[str, Any]] = None
    threat_intel: Optional[Dict[str, Any]] = None
    synthesized_yara_rule: Optional[str] = None
    synthesized_sigma_rule: Optional[str] = None
    rule_compilation_passed: Optional[bool] = None
    remediation_steps: Optional[List[Dict[str, Any]]] = None
    operator_approval_status: Optional[str] = None
    execution_results: Optional[List[Dict[str, Any]]] = None
    mesh_broadcast_status: Optional[Dict[str, Any]] = None
