"""OpenỌ̀ṣọ́ọ̀sì API tools for LangChain agent. Call OpenỌ̀ṣọ́ọ̀sì dashboard API."""
import os
import requests
from typing import Optional

OSOOSI_BASE = os.environ.get("OSOOSI_API_URL", "http://127.0.0.1:3030")


def _get(path: str) -> dict:
    r = requests.get(f"{OSOOSI_BASE}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def _post(path: str, json: Optional[dict] = None) -> dict:
    r = requests.post(f"{OSOOSI_BASE}{path}", json=json or {}, timeout=10)
    r.raise_for_status()
    return r.json()


def get_agent_context() -> str:
    """Get full OpenỌ̀ṣọ́ọ̀sì context: status, pending peers, threats, malware, repair status."""
    try:
        data = _get("/api/agent/context")
        import json
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error: {e}"


def approve_peer(peer_id: str) -> str:
    """Approve a pending peer to join the mesh. Use peer_id from pending_joins."""
    try:
        data = _post(f"/api/pending-joins/{peer_id}/allow")
        return f"Result: {data}"
    except Exception as e:
        return f"Error: {e}"


def deny_peer(peer_id: str) -> str:
    """Deny a pending peer from joining the mesh."""
    try:
        data = _post(f"/api/pending-joins/{peer_id}/deny")
        return f"Result: {data}"
    except Exception as e:
        return f"Error: {e}"


def trigger_patch_cycle() -> str:
    """Trigger patch discovery and apply. Uses OSOOSI_REPAIR_AUTO_APPLY."""
    try:
        data = _post("/api/agent/trigger-patch")
        return f"Result: {data}"
    except Exception as e:
        return f"Error: {e}"


def get_quarantined_peers() -> str:
    """List quarantined peers."""
    try:
        data = _get("/api/quarantined-peers")
        import json
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error: {e}"


def release_quarantined_peer(peer_id: str) -> str:
    """Release a peer from quarantine (localhost or admin host only)."""
    try:
        data = _post(f"/api/quarantined-peers/{peer_id}/release")
        return f"Result: {data}"
    except Exception as e:
        return f"Error: {e}"


def analyze_captured_traffic(limit: int = 20) -> str:
    """Analyze traffic captured by OpenỌ̀ṣọ́ọ̀sì (Sysmon NetworkConnect/DnsQuery). No pasting — reads from host telemetry."""
    try:
        data = _get(f"/api/traffic/analyze-captured?limit={limit}")
        import json
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error: {e}"


def triage_decide(threat_id: str, action: str) -> str:
    """Apply LLM triage decision for a high-confidence threat. Use when pending_triage has entries.
    Actions: Alert, Deception, Tarpit, GhostTarpit, Isolate."""
    try:
        data = _post("/api/triage/decide", {"threat_id": threat_id, "action": action})
        import json
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error: {e}"


def analyze_traffic_prompt(prompt: str) -> str:
    """Analyze TrafficLLM-style prompt: '<instruction> <packet> ...' via Rust API."""
    try:
        if "<packet>" not in prompt:
            return "Error: prompt must include '<packet>' marker"
        parts = prompt.split("<packet>", 1)
        human_instruction = parts[0].strip()
        traffic_data = "<packet>" + parts[1]
        data = _post("/api/traffic/conversation", {
            "human_instruction": human_instruction,
            "traffic_data": traffic_data,
        })
        import json
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error: {e}"
