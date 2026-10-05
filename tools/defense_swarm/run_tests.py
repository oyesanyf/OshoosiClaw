"""
Direct test runner for Defense Swarm test suite.
"""

import sys
import os
import traceback

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure src is on path
tools_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(tools_dir, "src"))
sys.path.insert(0, tools_dir)

from tests.test_triage import (
    test_triage_developer_cargo_build_benign,
    test_triage_malicious_mimikatz,
    test_triage_vssadmin_ransomware_blast_radius,
)
from tests.test_forensics import (
    test_forensics_vad_unbacked_memory,
    test_forensics_run_forensics_aggregation,
)
from tests.test_intel import (
    test_intel_mitre_injection_correlation,
    test_intel_cve_correlation,
)
from tests.test_rule_synth import (
    test_rule_synthesis_valid_generation,
    test_rule_synthesis_invalid_syntax_detection,
    test_run_rule_synthesis_node,
)
from tests.test_remediation import (
    test_immutable_safeguard_pid_immunity,
    test_immutable_safeguard_security_daemons,
    test_malicious_unprotected_target_remediation,
)
from tests.test_mesh_sync import (
    test_mesh_sync_gossipsub_payload_generation,
)
from tests.test_graph import (
    test_graph_benign_developer_execution,
    test_graph_malicious_interrupt_and_resume_approved,
    test_graph_malicious_interrupt_and_resume_rejected,
)
from tests.test_service import (
    test_health_endpoint,
    test_investigate_benign_incident,
    test_investigate_and_approval_flow,
    client,
)


def main():
    test_cases = [
        ("Triage - Developer Cargo Benign", test_triage_developer_cargo_build_benign),
        ("Triage - Mimikatz Malicious", test_triage_malicious_mimikatz),
        ("Triage - Vssadmin Blast Radius", test_triage_vssadmin_ransomware_blast_radius),
        ("Forensics - VAD Unbacked Memory", test_forensics_vad_unbacked_memory),
        ("Forensics - Aggregation", test_forensics_run_forensics_aggregation),
        ("Intel - MITRE T1055.012 Injection", test_intel_mitre_injection_correlation),
        ("Intel - CVE KEV Correlation", test_intel_cve_correlation),
        ("Rule Synth - Valid Rule Generation", test_rule_synthesis_valid_generation),
        ("Rule Synth - Syntax Error Detection", test_rule_synthesis_invalid_syntax_detection),
        ("Rule Synth - Node Execution", test_run_rule_synthesis_node),
        ("Remediation - Safeguard PID 0,1,4 Immunity", test_immutable_safeguard_pid_immunity),
        ("Remediation - Safeguard Security Daemons (Sysmon/Osoosi/MsMpEng)", test_immutable_safeguard_security_daemons),
        ("Remediation - Malicious Target Remediation", test_malicious_unprotected_target_remediation),
        ("Mesh Sync - GossipSub Payload Generation", test_mesh_sync_gossipsub_payload_generation),
        ("Graph - Benign Execution De-escalation", test_graph_benign_developer_execution),
        ("Graph - Attack Interrupt & Resume Approved", test_graph_malicious_interrupt_and_resume_approved),
        ("Graph - Attack Interrupt & Resume Rejected", test_graph_malicious_interrupt_and_resume_rejected),
    ]

    print("=" * 60)
    print(" Running Defense Swarm Test Suite")
    print("=" * 60)

    passed = 0
    failed = 0

    for name, fn in test_cases:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            traceback.print_exc()
            failed += 1

    # Service / API tests
    from starlette.testclient import TestClient
    from defense_swarm.service import app
    cli = TestClient(app)
    service_cases = [
        ("Service - Health Check Endpoint", lambda: test_health_endpoint(cli)),
        ("Service - Benign Investigation", lambda: test_investigate_benign_incident(cli)),
        ("Service - Interrupt & Approval Flow", lambda: test_investigate_and_approval_flow(cli)),
    ]

    for name, fn in service_cases:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            traceback.print_exc()
            failed += 1

    print("=" * 60)
    print(f" Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
