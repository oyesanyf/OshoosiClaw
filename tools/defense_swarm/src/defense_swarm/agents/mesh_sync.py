"""
Mesh Broadcaster / Fleet Immunizer Agent for LangGraph Defense Swarm.
Prepares distributed broadcast payloads for libp2p GossipSub topics:
- `osoosi-yara-v1`: Fleet-wide real-time YARA-X rule immunization
- `osoosi-skills-v1`: WikiSkill defensive tradecraft knowledge propagation
"""

from typing import Dict, Any
from datetime import datetime, timezone
import hashlib
from ..state import DefenseState


def generate_skill_markdown(state: DefenseState) -> str:
    incident_id = state.get("incident_id", "INC001")
    proc = state.get("target_process_name", "unknown.exe")
    threat_intel = state.get("threat_intel") or {}
    primary_tech = threat_intel.get("primary_technique", "T1055")
    yara = state.get("synthesized_yara_rule", "")

    return f"""# Autonomous Defense Pattern: {proc} ({primary_tech})

**Incident ID**: `{incident_id}`  
**Generated At**: {datetime.now(timezone.utc).isoformat()}  
**Primary MITRE Technique**: {primary_tech}  

## Incident Summary
OpenỌ̀ṣọ́ọ̀sì Autonomous Defense Swarm analyzed and neutralized execution of `{proc}`.

## Synthesized YARA Rule
```yara
{yara}
```

## Fleet Defense Guidance
- Enforce process integrity checks for `{proc}`.
- Isolate any unbacked executable VAD allocations.
"""


def run_mesh_sync(state: DefenseState) -> Dict[str, Any]:
    """
    Assembles GossipSub mesh immunization packages and returns broadcast metadata.
    """
    yara_rule = state.get("synthesized_yara_rule") or ""
    skill_md = generate_skill_markdown(state)
    skill_hash = hashlib.sha256(skill_md.encode("utf-8")).hexdigest()

    now_iso = datetime.now(timezone.utc).isoformat()
    yara_payload = {
        "topic": "osoosi-yara-v1",
        "rule_name": f"swarm_rule_{state.get('incident_id', 'INC001')}",
        "rule_content": yara_rule,
        "timestamp": now_iso,
    }

    skills_payload = {
        "topic": "osoosi-skills-v1",
        "skill_name": "swarm_incident_immunization",
        "version": "1.0.0",
        "pattern_title": f"Defense against {state.get('target_process_name', 'malware')}",
        "markdown_content": skill_md,
        "content_hash": skill_hash,
    }

    return {
        "mesh_broadcast_status": {
            "gossipsub_yara_queued": bool(yara_rule),
            "gossipsub_skills_queued": True,
            "nostr_pulse_queued": True,
            "yara_payload": yara_payload,
            "skills_payload": skills_payload,
            "broadcast_timestamp": now_iso,
        }
    }
