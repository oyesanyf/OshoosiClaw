from typing import TypedDict, List, Dict, Optional, Any


class DefenseState(TypedDict, total=False):
    """
    Typed state schema for OpenỌ̀ṣọ́ọ̀sì LangGraph Defense Swarm.
    Maintains incident context, forensic artifacts, synthesized detection rules,
    and remediation actions throughout the multi-agent graph lifecycle.
    """
    incident_id: str
    timestamp: str

    # Fast-Ring Ingestion Data
    target_pid: int
    target_process_name: str
    target_path: str
    command_line: str
    parent_pid: int
    parent_process_name: str
    initial_detection_engine: str  # "sigma", "yara", "clef", "driver", "model"
    initial_confidence: float

    # Ring-1 Agent Enrichments
    triage_verdict: str  # "MALICIOUS", "SUSPICIOUS", "BENIGN"
    blast_radius_score: float

    forensic_findings: Dict[str, Any]  # VAD unbacked memory, MFT anomalies, sockets
    threat_intel: Dict[str, Any]  # MITRE techniques, CVEs, KEV status

    synthesized_yara_rule: Optional[str]
    synthesized_sigma_rule: Optional[str]
    rule_compilation_passed: bool
    compiler_error_log: Optional[str]
    rule_synth_retries: int

    remediation_steps: List[Dict[str, Any]]
    operator_approval_status: str  # "PENDING", "APPROVED", "REJECTED", "AUTO_APPROVED"
    operator_feedback: Optional[str]

    execution_results: List[Dict[str, Any]]
    mesh_broadcast_status: Dict[str, Any]  # GossipSub osoosi-yara-v1, osoosi-skills-v1, Nostr
