"""
Command-line interface for OpenỌ̀ṣọ́ọ̀sì LangGraph Autonomous Defense Swarm.
Enables starting the FastAPI service, running test incidents, querying status,
and managing Human-in-the-Loop approval checkpoints.
"""

import argparse
import sys
import json
import httpx
import uvicorn
from typing import Optional
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .state import DefenseState
from .graph import build_defense_swarm_graph

DEFAULT_SERVICE_URL = "http://127.0.0.1:4002"


def cmd_serve(args):
    """Starts the uvicorn FastAPI server."""
    print(f"[*] Starting OpenOshoosi Defense Swarm on {args.host}:{args.port}...")
    uvicorn.run(
        "defense_swarm.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


def cmd_status(args):
    """Queries health or incident status from the running swarm daemon."""
    url = args.url.rstrip("/")
    incident_id = getattr(args, "incident_id", None)
    if incident_id:
        req_url = f"{url}/api/swarm/status/{incident_id}"
    else:
        req_url = f"{url}/api/swarm/health"

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(req_url)
            if resp.status_code == 200:
                print(json.dumps(resp.json(), indent=2))
            else:
                print(f"[!] Request returned status {resp.status_code}: {resp.text}")
                sys.exit(1)
    except httpx.ConnectError:
        print(f"[!] Failed to connect to Defense Swarm service at {url}.")
        print("    Ensure the service is running via: defense-swarm serve")
        sys.exit(1)


def cmd_test_incident(args):
    """Runs a synthetic attack incident through the LangGraph StateGraph pipeline."""
    graph = build_defense_swarm_graph()
    incident_id = f"TEST-INC-{int(datetime.now(timezone.utc).timestamp())}"

    print("\n================================================================================")
    print("       OpenOshoosi LangGraph Autonomous Defense Swarm: Test Execution")
    print("================================================================================")
    print(f"Incident ID:    {incident_id}")
    print(f"Target PID:     {args.pid}")
    print(f"Target Process: {args.process}")
    print(f"Command Line:   {args.command_line}")
    print("--------------------------------------------------------------------------------")

    state: DefenseState = {
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_pid": args.pid,
        "target_process_name": args.process,
        "target_path": getattr(args, "path", f"C:\\Windows\\Temp\\{args.process}"),
        "command_line": args.command_line,
        "parent_pid": 1000,
        "parent_process_name": "cmd.exe",
        "initial_detection_engine": "cli-test",
        "initial_confidence": getattr(args, "confidence", 0.95),
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
        "operator_approval_status": "AUTO_APPROVED",
        "operator_feedback": None,
        "execution_results": [],
        "mesh_broadcast_status": {},
    }

    config = {"configurable": {"thread_id": incident_id}}
    result = graph.invoke(state, config=config)

    print(f"[+] Triage Verdict:         {result.get('triage_verdict')}")
    print(f"[+] Blast Radius Score:     {result.get('blast_radius_score')}")
    print(f"[+] Primary MITRE Tech:     {result.get('threat_intel', {}).get('primary_technique')}")
    print(f"[+] Rule Compilation:      {'PASSED' if result.get('rule_compilation_passed') else 'FAILED'}")
    print(f"\n[+] Synthesized YARA Rule:\n{result.get('synthesized_yara_rule', 'None')}")
    print(f"\n[+] Remediation Steps ({len(result.get('remediation_steps', []))}):")
    for step in result.get("remediation_steps", []):
        print(f"    - [{step.get('action')}] {step.get('target')} ({step.get('status')}): {step.get('reason')}")
    print(f"\n[+] Mesh GossipSub Status:   {result.get('mesh_broadcast_status', {}).get('gossipsub_yara_queued')}")
    print("================================================================================\n")


def cmd_investigate(args):
    """Submits an incident for investigation to the swarm service."""
    url = args.url.rstrip("/")
    payload = {
        "incident_id": args.incident_id,
        "target_pid": args.pid,
        "target_process_name": args.name,
        "target_path": args.path,
        "command_line": args.cmd,
        "initial_confidence": args.confidence,
    }

    print(f"[*] Dispatching investigation for PID {args.pid} ({args.name})...")
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{url}/api/swarm/investigate", json=payload)
            if resp.status_code == 200:
                res = resp.json()
                print("[+] Investigation started!")
                print(f"    Incident ID: {res.get('incident_id')}")
                print(f"    Status:      {res.get('status')}")
            else:
                print(f"[!] Error {resp.status_code}: {resp.text}")
                sys.exit(1)
    except httpx.ConnectError:
        print("[!] Swarm service offline. Falling back to local in-process execution...")
        args.process = args.name
        args.command_line = args.cmd
        cmd_test_incident(args)


def cmd_approve(args):
    """Approves a pending incident remediation plan."""
    url = args.url.rstrip("/")
    payload = {
        "decision": "APPROVED",
        "operator_feedback": args.feedback or "Approved via CLI",
    }
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(f"{url}/api/swarm/approve/{args.incident_id}", json=payload)
            if resp.status_code == 200:
                print(f"[+] Incident {args.incident_id} approved!")
                print(json.dumps(resp.json(), indent=2))
            else:
                print(f"[!] Error {resp.status_code}: {resp.text}")
    except httpx.ConnectError:
        print(f"[!] Could not connect to Defense Swarm service at {url}.")


def cmd_reject(args):
    """Rejects a pending incident remediation plan."""
    url = args.url.rstrip("/")
    payload = {
        "decision": "REJECTED",
        "operator_feedback": args.feedback or "Rejected via CLI",
    }
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(f"{url}/api/swarm/approve/{args.incident_id}", json=payload)
            if resp.status_code == 200:
                print(f"[+] Incident {args.incident_id} rejected.")
                print(json.dumps(resp.json(), indent=2))
            else:
                print(f"[!] Error {resp.status_code}: {resp.text}")
    except httpx.ConnectError:
        print(f"[!] Could not connect to Defense Swarm service at {url}.")


def main():
    parser = argparse.ArgumentParser(
        prog="defense-swarm",
        description="OpenỌ̀ṣọ́ọ̀sì LangGraph Autonomous Defense Swarm CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # serve / start
    p_serve = subparsers.add_parser("serve", help="Run the FastAPI REST server")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=4002, help="Bind port (default: 4002)")
    p_serve.add_argument("--reload", action="store_true", help="Enable auto-reload")
    p_serve.set_defaults(func=cmd_serve)

    p_start = subparsers.add_parser("start", help="Alias for serve")
    p_start.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_start.add_argument("--port", type=int, default=4002, help="Bind port (default: 4002)")
    p_start.add_argument("--reload", action="store_true", help="Enable auto-reload")
    p_start.set_defaults(func=cmd_serve)

    # test-incident / run
    p_test = subparsers.add_parser("test-incident", help="Run synthetic test incident through StateGraph")
    p_test.add_argument("--pid", type=int, default=4444, help="Target PID")
    p_test.add_argument("--process", default="decoy_ransomware.exe", help="Target process name")
    p_test.add_argument("--command-line", default="decoy_ransomware.exe -encrypt C:\\Users\\Public", help="Command line")
    p_test.set_defaults(func=cmd_test_incident)

    p_run = subparsers.add_parser("run", help="Alias for test-incident")
    p_run.add_argument("--pid", type=int, default=4444, help="Target PID")
    p_run.add_argument("--process", default="decoy_ransomware.exe", help="Target process name")
    p_run.add_argument("--command-line", default="decoy_ransomware.exe -encrypt C:\\Users\\Public", help="Command line")
    p_run.set_defaults(func=cmd_test_incident)

    # status
    p_status = subparsers.add_parser("status", help="Query swarm health or incident status")
    p_status.add_argument("--url", default=DEFAULT_SERVICE_URL, help="Swarm service URL")
    p_status.add_argument("--incident-id", help="Optional specific incident ID to check")
    p_status.set_defaults(func=cmd_status)

    # investigate
    p_inv = subparsers.add_parser("investigate", help="Trigger an incident investigation")
    p_inv.add_argument("--url", default=DEFAULT_SERVICE_URL, help="Swarm service URL")
    p_inv.add_argument("--incident-id", help="Optional specific incident ID")
    p_inv.add_argument("--pid", type=int, default=0, help="Target process ID")
    p_inv.add_argument("--name", default="suspicious.exe", help="Target process name")
    p_inv.add_argument("--path", default="", help="Target executable path")
    p_inv.add_argument("--cmd", default="", help="Command line string")
    p_inv.add_argument("--confidence", type=float, default=0.85, help="Initial threat confidence (0.0 - 1.0)")
    p_inv.set_defaults(func=cmd_investigate)

    # approve
    p_app = subparsers.add_parser("approve", help="Approve an incident remediation plan")
    p_app.add_argument("incident_id", help="Incident ID to approve")
    p_app.add_argument("--feedback", help="Approval remarks or notes")
    p_app.add_argument("--url", default=DEFAULT_SERVICE_URL, help="Swarm service URL")
    p_app.set_defaults(func=cmd_approve)

    # reject
    p_rej = subparsers.add_parser("reject", help="Reject an incident remediation plan")
    p_rej.add_argument("incident_id", help="Incident ID to reject")
    p_rej.add_argument("--feedback", help="Rejection rationale")
    p_rej.add_argument("--url", default=DEFAULT_SERVICE_URL, help="Swarm service URL")
    p_rej.set_defaults(func=cmd_reject)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
