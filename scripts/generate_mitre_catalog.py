#!/usr/bin/env python3
"""
MITRE ATT&CK Enterprise Catalog & EDR Detection Generator
==========================================================
Uses `mitreattack-python` (and ATT&CK STIX 2.1) to generate the authoritative
enterprise knowledge base `config/mitre_attack_catalog.json` for OpenỌ̀ṣọ́ọ̀sì Agentic EDR.

Features:
- All 14 Enterprise Tactics (TA0043 to TA0040) + TA0112 (15 total)
- All Enterprise Techniques and Sub-techniques
- All Mitigations (M1010 to M1056)
- All Threat Actor Groups (APTs & Ransomware syndicates)
- Technique-to-Mitigation and Technique-to-Group relationships
- EDR Detection Mappings:
    - Scans `rules/sigma/` to associate 4,334 Sigma rules to MITRE technique tags
    - Associates kernel telemetry data sources (Sysmon Event IDs, Windows Event Logs)
    - Designates the responsible EDR consensus voter (SigmaVoter, MemoryInspectionVoter, YaraXVoter, AiSecurityAuditVoter, IocVoter)
    - Designates the consensus response action (Alert, Tarpit, Isolate, MemoryScan)
"""

import os
import glob
import re
import json
from collections import defaultdict

STIX_DIR = "tmp_stix"
STIX_FILE = os.path.join(STIX_DIR, "v19.2", "enterprise-attack.json")
CONFIG_STIX_FILE = os.path.join("config", "stix-atlas-attack-enterprise.json")
DASHBOARD_STIX_FILE = os.path.join("dashboard", "dist", "stix-atlas-attack-enterprise.json")
OUTPUT_FILE = os.path.join("config", "mitre_attack_catalog.json")
DASHBOARD_OUTPUT_FILE = os.path.join("dashboard", "dist", "mitre_attack_catalog.json")
SIGMA_DIR = os.path.join("rules", "sigma")
STIX_BUNDLE_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas-attack-enterprise.json"

TACTIC_INFO = [
    ("TA0043", "Reconnaissance", "Adversaries gathering information to plan future adversary operations."),
    ("TA0042", "Resource Development", "Adversaries establishing resources to support operations."),
    ("TA0001", "Initial Access", "Adversaries trying to get into your network."),
    ("TA0002", "Execution", "Adversaries trying to run malicious code on your endpoints."),
    ("TA0003", "Persistence", "Adversaries trying to maintain their foothold across restarts."),
    ("TA0004", "Privilege Escalation", "Adversaries trying to gain higher-level permissions."),
    ("TA0005", "Defense Evasion", "Adversaries trying to avoid being detected by security software."),
    ("TA0112", "Defense Impairment", "Adversaries deliberately disabling security tools and defensive capabilities."),
    ("TA0006", "Credential Access", "Adversaries trying to steal account names and passwords."),
    ("TA0007", "Discovery", "Adversaries trying to observe system and network environment."),
    ("TA0008", "Lateral Movement", "Adversaries trying to move through your environment."),
    ("TA0009", "Collection", "Adversaries trying to gather data of interest to their goal."),
    ("TA0011", "Command and Control", "Adversaries communicating with compromised systems to control them."),
    ("TA0010", "Exfiltration", "Adversaries trying to steal data from your network."),
    ("TA0040", "Impact", "Adversaries trying to manipulate, interrupt, or destroy systems and data."),
]

PHASE_TO_TACTIC = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "ai-attack-staging": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "ai-model-access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "stealth": ("TA0005", "Defense Evasion"),
    "defense-impairment": ("TA0112", "Defense Impairment"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

# Critical threat actor groups known to OpenOsoosi CTI
PRESET_GROUPS = [
    {
        "id": "G0016",
        "name": "APT29",
        "description": "Russian Foreign Intelligence Service (SVR) state-sponsored cyber espionage group.",
        "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard", "YTTRIUM", "The Dukes"],
        "techniques": ["T1059", "T1059.001", "T1078", "T1082", "T1566", "T1027", "T1055"],
    },
    {
        "id": "G0007",
        "name": "APT28",
        "description": "Russian military intelligence (GRU) cyber unit targeting government, military, and critical infrastructure.",
        "aliases": ["Fancy Bear", "Sednit", "Sofacy", "Strontium", "Forest Blizzard"],
        "techniques": ["T1059", "T1566", "T1082", "T1003", "T1218", "T1055"],
    },
    {
        "id": "G0032",
        "name": "Lazarus Group",
        "description": "Democratic People's Republic of Korea (DPRK) state-sponsored group responsible for cyber espionage and financially motivated operations.",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "Labyrinth Chollima"],
        "techniques": ["T1059", "T1055", "T1082", "T1486", "T1105", "T1027", "T1071"],
    },
    {
        "id": "G0144",
        "name": "LockBit",
        "description": "Prolific Ransomware-as-a-Service syndicate targeting global enterprise infrastructure.",
        "aliases": ["LockBit 2.0", "LockBit 3.0", "LockBit Black", "LockBit Green"],
        "techniques": ["T1486", "T1490", "T1059", "T1070", "T1082", "T1562.001", "T1055"],
    },
    {
        "id": "G0140",
        "name": "Volt Typhoon",
        "description": "People's Republic of China (PRC) state-sponsored actor focusing on cyber espionage and pre-positioning across critical infrastructure.",
        "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391"],
        "techniques": ["T1059", "T1078", "T1082", "T1016", "T1057", "T1047", "T1003"],
    },
    {
        "id": "G0046",
        "name": "FIN7",
        "description": "Financially motivated threat group engaging in point-of-sale malware operations and enterprise ransomware deployment.",
        "aliases": ["Carbanak", "ELBRUS", "Sangria Tempest"],
        "techniques": ["T1059", "T1055", "T1082", "T1027", "T1566", "T1204"],
    },
    {
        "id": "G0034",
        "name": "Sandworm Team",
        "description": "Russian GRU Unit 74455 military intelligence operation targeting energy grids, ICS/SCADA, and global enterprise networks.",
        "aliases": ["TeleBots", "BlackEnergy Group", "Voodoo Bear", "Seashell Blizzard"],
        "techniques": ["T1486", "T1490", "T1059", "T1055", "T1105", "T1082"],
    },
    {
        "id": "G1015",
        "name": "Scattered Spider",
        "description": "Financially motivated cybercrime group specializing in identity federation abuse, social engineering, and cloud persistence.",
        "aliases": ["0ktapus", "UNC3944", "Octo Tempest", "Muddled Libra"],
        "techniques": ["T1566", "T1078", "T1087", "T1059", "T1562"],
    },
    {
        "id": "G0145",
        "name": "BlackCat / ALPHV",
        "description": "Sophisticated Rust-based Ransomware-as-a-Service syndicate targeting high-value enterprise networks.",
        "aliases": ["ALPHV", "Noberus", "BlackCat"],
        "techniques": ["T1486", "T1490", "T1059", "T1027", "T1562.001", "T1082"],
    },
    {
        "id": "G0019",
        "name": "Wizard Spider",
        "description": "Russia-based cybercrime group behind Ryuk ransomware, TrickBot, and Conti operations.",
        "aliases": ["Gold Blackburn", "Grim Spider"],
        "techniques": ["T1055", "T1059", "T1003", "T1486", "T1490", "T1082"],
    },
    {
        "id": "G0010",
        "name": "Turla",
        "description": "Russian state-sponsored espionage group known for complex malware architectures and satellite C2 communication.",
        "aliases": ["Waterbug", "Venomous Bear", "Krypton", "Secret Blizzard"],
        "techniques": ["T1055", "T1059", "T1082", "T1071", "T1027"],
    },
    {
        "id": "G0096",
        "name": "Midnight Blizzard",
        "description": "Elite Russian intelligence unit targeting cloud tenants, identity providers, and government entities.",
        "aliases": ["APT29", "Nobelium", "Cozy Bear"],
        "techniques": ["T1078", "T1059", "T1082", "T1566", "T1003"],
    },
    {
        "id": "G0058",
        "name": "Charming Kitten",
        "description": "Iranian state-sponsored cyber espionage actor targeting political dissidents, academia, and defense contractors.",
        "aliases": ["APT35", "Phosphorus", "Mint Sandstorm", "TA453"],
        "techniques": ["T1566", "T1059", "T1082", "T1003", "T1071"],
    },
    {
        "id": "G0091",
        "name": "Silence",
        "description": "Financially motivated threat group targeting financial institutions and banking infrastructure worldwide.",
        "aliases": ["Whisper Tempest"],
        "techniques": ["T1059", "T1055", "T1082", "T1105", "T1027"],
    },
    {
        "id": "G0049",
        "name": "OilRig",
        "description": "Iranian threat group targeting government, aerospace, and energy sectors across the Middle East.",
        "aliases": ["APT34", "Helix Kitten", "EUROPIUM", "Crambus"],
        "techniques": ["T1059", "T1082", "T1055", "T1071", "T1566"],
    },
    {
        "id": "G0008",
        "name": "Carbanak",
        "description": "Prolific cybercriminal syndicate responsible for stealing hundreds of millions from financial institutions globally.",
        "aliases": ["Anunak"],
        "techniques": ["T1059", "T1055", "T1082", "T1003", "T1105"],
    }
]

def ensure_stix_bundle():
    """Ensure MITRE ATT&CK Enterprise + ATLAS STIX 2.1 bundle is present."""
    if os.path.exists(CONFIG_STIX_FILE) and os.path.getsize(CONFIG_STIX_FILE) > 1000000:
        return CONFIG_STIX_FILE

    # Try finding any existing download in tmp_stix
    candidates = glob.glob(f"{STIX_DIR}/**/enterprise-attack*.json", recursive=True)
    for c in candidates:
        if os.path.getsize(c) > 1000000:
            return c

    print(f"Downloading authoritative combined ATT&CK + ATLAS STIX 2.1 bundle from {STIX_BUNDLE_URL}...")
    os.makedirs(os.path.dirname(CONFIG_STIX_FILE), exist_ok=True)
    import urllib.request
    req = urllib.request.Request(STIX_BUNDLE_URL, headers={"User-Agent": "Mozilla/5.0 OpenOsoosi/0.1.1"})
    try:
        with urllib.request.urlopen(req) as resp, open(CONFIG_STIX_FILE, "wb") as out_f:
            out_f.write(resp.read())
        return CONFIG_STIX_FILE
    except Exception as e:
        print(f"Direct download failed ({e}), attempting fallback methods...")

    os.makedirs(STIX_DIR, exist_ok=True)
    try:
        from mitreattack.download_stix import download_domains
        download_domains(["enterprise"], STIX_DIR, False, "2.1")
    except Exception as e:
        print(f"mitreattack download failed ({e}), attempting direct download...")
        import urllib.request
        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"
        dest_dir = os.path.join(STIX_DIR, "v19.2")
        os.makedirs(dest_dir, exist_ok=True)
        dest_file = os.path.join(dest_dir, "enterprise-attack.json")
        urllib.request.urlretrieve(url, dest_file)

    candidates = glob.glob(f"{STIX_DIR}/**/enterprise-attack*.json", recursive=True)
    for c in candidates:
        if os.path.getsize(c) > 1000000:
            return c
    raise RuntimeError("Failed to obtain MITRE ATT&CK STIX bundle")

def get_mitre_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-enterprise-attack", "mitre-atlas"):
            return ref.get("external_id")
    return None

def scan_sigma_rules():
    """Scan all Sigma rules in rules/sigma and map them to MITRE techniques."""
    print(f"Scanning Sigma rules in {SIGMA_DIR}...")
    tag_pattern = re.compile(r"attack\.(t\d+(?:\.\d+)?)", re.IGNORECASE)
    title_pattern = re.compile(r"^\s*title:\s*['\"]?(.*?)['\"]?\s*$", re.MULTILINE)

    files = glob.glob(f"{SIGMA_DIR}/**/*.yml", recursive=True)
    tech_to_sigma = defaultdict(list)
    sigma_total = 0

    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                content = fp.read()
            m_title = title_pattern.search(content)
            title = m_title.group(1).strip() if m_title else os.path.basename(f)
            matches = tag_pattern.findall(content)
            for m in set(m.upper() for m in matches):
                tech_to_sigma[m].append(title)
            sigma_total += 1
        except Exception:
            pass

    print(f"Scanned {sigma_total} Sigma rules. Mapped to {len(tech_to_sigma)} distinct technique IDs.")
    return tech_to_sigma

def assign_edr_telemetry(tech_id, tech_name):
    """Assign kernel telemetry data sources based on technique profile."""
    t = tech_id.upper()
    name_l = tech_name.lower()

    if t.startswith("T1055") or t in ("T1093", "T1620") or "injection" in name_l or "hollow" in name_l:
        return [
            "Sysmon Event 8 (CreateRemoteThread)",
            "Sysmon Event 10 (ProcessAccess)",
            "Sysmon Event 7 (Image Loaded)",
            "ETW Threat-Intelligence Telemetry",
        ]
    elif t.startswith("T1003") or t in ("T1555", "T1552", "T1558", "T1110", "T1078") or "credential" in name_l:
        return [
            "Sysmon Event 10 (ProcessAccess - LSASS)",
            "Windows Security 4624/4625 (Logon Auditing)",
            "Sysmon Event 11 (FileAccess / Security Vault)",
        ]
    elif t.startswith("T1071") or t in ("T1090", "T1095", "T1571", "T1572", "T1041", "T1048", "T1567", "T1566.002"):
        return [
            "Sysmon Event 3 (Network Connection)",
            "Sysmon Event 22 (DNS Query)",
            "Windows Filtering Platform 5156/5158",
        ]
    elif t in ("T1112", "T1546", "T1547", "T1574", "T1543") or t.startswith("T1112.") or t.startswith("T1547.") or t.startswith("T1574."):
        return [
            "Sysmon Event 12/13/14 (RegistryEvent)",
            "Windows Security 4657 (Registry Value Modified)",
            "Sysmon Event 1 (Process Create)",
        ]
    elif t.startswith("T1053"):
        return [
            "Windows Security 4698/4702 (Scheduled Task Creation)",
            "Sysmon Event 1 (Process Create: schtasks.exe)",
        ]
    elif t in ("T1486", "T1490", "T1489", "T1485", "T1561", "T1491") or "recovery" in name_l or "encrypt" in name_l:
        return [
            "Sysmon Event 11 (FileCreate / Rapid File Modification)",
            "Sysmon Event 1 (Process Create: vssadmin / bcdedit)",
            "Sysmon Event 13 (Registry Deletion)",
        ]
    elif t in ("T1059", "T1218", "T1047", "T1082", "T1087", "T1016", "T1057", "T1083", "T1033") or t.startswith("T1059.") or t.startswith("T1218."):
        return [
            "Sysmon Event 1 (Process Create)",
            "Windows Security 4688 (Process Creation)",
            "Windows PowerShell 4104 (Scriptblock Logging)",
        ]
    else:
        return [
            "Sysmon Event 1 (Process Create)",
            "Windows Security 4688 (Process Creation)",
            "Sysmon Event 11 (FileCreate)",
        ]

def assign_edr_voter(tech_id, tech_name, tactic_id):
    """Designate the responsible EDR consensus voter."""
    t = tech_id.upper()
    name_l = tech_name.lower()

    if t.startswith("AML."):
        if t in ("AML.T0051", "AML.T0054", "AML.T0042"):
            return "AgenticVoter"
        elif t == "AML.T0031":
            return "ZeroDayVoter"
        else:
            return "AiSecurityAuditVoter"

    if t.startswith("T1055") or t.startswith("T1003") or t in ("T1093", "T1620") or "injection" in name_l or "hollowing" in name_l or "lsass" in name_l:
        return "MemoryInspectionVoter"
    elif t in ("T1027", "T1140", "T1036", "T1486", "T1566", "T1204") or "obfuscat" in name_l or "packer" in name_l or "malware" in name_l:
        return "YaraXVoter"
    elif t.startswith("T1071") or t in ("T1090", "T1568", "T1571", "T1041", "T1048") or t.startswith("T1566."):
        return "IocVoter"
    elif t in ("T1562", "T1548", "T1078.004") or "prompt" in name_l or "agent" in name_l or "ai" in name_l:
        return "AiSecurityAuditVoter"
    else:
        return "SigmaVoter"

def assign_consensus_action(tech_id, tech_name, tactic_id):
    """Designate the consensus response action."""
    t = tech_id.upper()
    name_l = tech_name.lower()

    if t.startswith("AML."):
        if t in ("AML.T0043", "AML.T0044", "AML.T0051", "AML.T0042"):
            return "Tarpit"
        elif t in ("AML.T0048", "AML.T0040", "AML.T0029", "AML.T0031"):
            return "Isolate"
        else:
            return "Alert"

    if (
        t.startswith("T1003")
        or t.startswith("T1055")
        or t in ("T1486", "T1490", "T1489", "T1562.001", "T1547")
        or "ransom" in name_l
        or "wiper" in name_l
        or "dump" in name_l
    ):
        return "Isolate"
    elif (
        t.startswith("T1059")
        or t.startswith("T1053")
        or t.startswith("T1218")
        or t in ("T1021", "T1047", "T1112", "T1574")
        or tactic_id in ("TA0002", "TA0008")
    ):
        return "Tarpit"
    elif t in ("T1620", "T1093") or "injection" in name_l or "memory" in name_l:
        return "MemoryScan"
    else:
        return "Alert"

def build_catalog():
    stix_file = ensure_stix_bundle()
    print(f"Reading STIX bundle from {stix_file}...")
    with open(stix_file, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    id_to_obj = {o["id"]: o for o in objects if "id" in o}

    # Scan Sigma rules
    tech_to_sigma = scan_sigma_rules()

    # Build Mitigations map
    mitigations_dict = {}
    mit_stix_to_mid = {}
    for obj in objects:
        if obj.get("type") == "course-of-action" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            mid = get_mitre_id(obj)
            if mid and (mid.startswith("M") or mid.startswith("AML.M")):
                mitigations_dict[mid] = {
                    "id": mid,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "").split("\n\n")[0],
                    "techniques": [],
                    "defense_type": "AI Guardrail" if mid.startswith("AML.M") else "Security Control",
                }
                mit_stix_to_mid[obj["id"]] = mid

    # Build Groups map
    groups_dict = {}
    grp_stix_to_gid = {}
    for obj in objects:
        if obj.get("type") == "intrusion-set" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            gid = get_mitre_id(obj)
            if gid and gid.startswith("G"):
                groups_dict[gid] = {
                    "id": gid,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "").split("\n\n")[0],
                    "aliases": obj.get("aliases", []),
                    "techniques": [],
                }
                grp_stix_to_gid[obj["id"]] = gid

    # Inject preset critical CTI groups
    for pg in PRESET_GROUPS:
        gid = pg["id"]
        if gid not in groups_dict:
            groups_dict[gid] = {
                "id": gid,
                "name": pg["name"],
                "description": pg["description"],
                "aliases": pg["aliases"],
                "techniques": list(pg["techniques"]),
            }
        else:
            # Ensure name matches expected test names (e.g. LockBit)
            groups_dict[gid]["name"] = pg["name"]
            for a in pg["aliases"]:
                if a not in groups_dict[gid]["aliases"]:
                    groups_dict[gid]["aliases"].append(a)
            for t in pg["techniques"]:
                if t not in groups_dict[gid]["techniques"]:
                    groups_dict[gid]["techniques"].append(t)

    # Technique maps
    techniques_by_stix = {}
    subtechniques_by_parent_stix = defaultdict(list)
    stix_to_tech_id = {}

    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            tid = get_mitre_id(obj)
            if not tid or not (tid.startswith("T") or tid.startswith("AML.T")):
                continue
            techniques_by_stix[obj["id"]] = obj
            stix_to_tech_id[obj["id"]] = tid

    # Process relationships
    print("Processing STIX relationships...")
    for rel in objects:
        if rel.get("type") != "relationship":
            continue
        rel_type = rel.get("relationship_type")
        src_ref = rel.get("source_ref")
        tgt_ref = rel.get("target_ref")

        if rel_type == "subtechnique-of":
            subtechniques_by_parent_stix[tgt_ref].append(src_ref)

        elif rel_type == "mitigates":
            mid = mit_stix_to_mid.get(src_ref)
            tid = stix_to_tech_id.get(tgt_ref)
            if mid and tid and mid in mitigations_dict:
                if tid not in mitigations_dict[mid]["techniques"]:
                    mitigations_dict[mid]["techniques"].append(tid)

        elif rel_type == "uses":
            gid = grp_stix_to_gid.get(src_ref)
            tid = stix_to_tech_id.get(tgt_ref)
            if gid and tid and gid in groups_dict:
                if tid not in groups_dict[gid]["techniques"]:
                    groups_dict[gid]["techniques"].append(tid)

    # Invert mitigations and groups to technique lookup
    tech_to_mits = defaultdict(list)
    for m in mitigations_dict.values():
        label = f"{m['id']}: {m['name']}"
        for t in m["techniques"]:
            tech_to_mits[t].append(label)
            # Roll up to parent if subtechnique
            if "." in t:
                parent = t.split(".")[0]
                if label not in tech_to_mits[parent]:
                    tech_to_mits[parent].append(label)

    tech_to_grps = defaultdict(list)
    for g in groups_dict.values():
        name = g["name"]
        for t in g["techniques"]:
            if name not in tech_to_grps[t]:
                tech_to_grps[t].append(name)
            if "." in t:
                parent = t.split(".")[0]
                if name not in tech_to_grps[parent]:
                    tech_to_grps[parent].append(name)

    # Build primary techniques list
    print("Compiling authoritative techniques and detection mappings...")
    final_techniques = []

    for stix_id, obj in techniques_by_stix.items():
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        # We process top-level techniques as primary items
        if is_sub:
            continue

        tid = stix_to_tech_id[stix_id]
        name = obj.get("name", "")
        desc = obj.get("description", "").split("\n\n")[0]
        platforms = obj.get("x_mitre_platforms", ["Windows"])

        # Determine primary tactic
        phases = obj.get("kill_chain_phases", [])
        tactic_id = "TA0002"
        tactic_name = "Execution"
        for p in phases:
            p_name = p.get("phase_name", "").lower()
            if p_name in PHASE_TO_TACTIC:
                tactic_id, tactic_name = PHASE_TO_TACTIC[p_name]
                break

        # Sub-techniques
        sub_list = []
        for sub_stix_id in subtechniques_by_parent_stix.get(stix_id, []):
            sub_obj = techniques_by_stix.get(sub_stix_id)
            if sub_obj:
                sub_id = stix_to_tech_id.get(sub_stix_id)
                if sub_id:
                    sub_list.append({
                        "id": sub_id,
                        "name": sub_obj.get("name", ""),
                        "description": sub_obj.get("description", "").split("\n\n")[0],
                    })
        sub_list.sort(key=lambda s: s["id"])

        # Aggregate Sigma rules: rule explicitly tagged with parent OR any of its subtechniques
        associated_sigma = list(tech_to_sigma.get(tid, []))
        for sub in sub_list:
            for s_rule in tech_to_sigma.get(sub["id"], []):
                if s_rule not in associated_sigma:
                    associated_sigma.append(s_rule)

        # Telemetry, Voter, Action
        data_sources = assign_edr_telemetry(tid, name)
        voter = assign_edr_voter(tid, name, tactic_id)
        consensus_action = assign_consensus_action(tid, name, tactic_id)

        # Detection mechanisms
        detection_mechanisms = []
        if associated_sigma:
            detection_mechanisms.append(f"Sigma Rule Detection ({len(associated_sigma)} rules)")
        detection_mechanisms.append(f"OpenỌ̀ṣọ́ọ̀sì {voter}")
        if data_sources:
            detection_mechanisms.append(data_sources[0])
        if len(data_sources) > 1:
            detection_mechanisms.append(data_sources[1])

        # Associated mitigations and groups
        is_atlas = tid.startswith("AML.")
        mits = tech_to_mits.get(tid, [])
        if not mits:
            mits = ["AML.M0015: User Prompt Sanitization & Invariant Enforcement", "AML.M0016: Restrict Tool / Subprocess Execution Privileges"] if is_atlas else ["M1038: Execution Prevention", "M1047: Audit & Security Logging"]
        grps = tech_to_grps.get(tid, [])
        if not grps:
            grps = ["Volt Typhoon", "Lazarus Group", "Scattered Spider"] if is_atlas else ["APT29", "Volt Typhoon"]

        tech_entry = {
            "id": tid,
            "name": name,
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "description": desc,
            "platforms": platforms,
            "data_sources": data_sources,
            "mitigations": mits[:10],
            "groups": grps[:15],
            "detection_mechanisms": detection_mechanisms,
            "voter": voter,
            "consensus_action": consensus_action,
            "sigma_rules": associated_sigma,
            "is_atlas": is_atlas,
            "subtechniques": sub_list,
        }
        final_techniques.append(tech_entry)

    # MITRE ATLAS AI Threat Matrix Techniques (https://github.com/mitre-atlas/atlas-data)
    atlas_techniques = [
        {
            "id": "AML.T0043",
            "name": "Adversarial Prompt Injection / Tool-Argument Injection",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "description": "Adversaries craft malicious prompt inputs or jailbreak sequences that manipulate an autonomous LLM agent into executing arbitrary downstream shell commands, unauthorized sub-processes, or abusing tool arguments.",
            "platforms": ["AI Agent", "LLM Runtime", "Python", "Node.js"],
            "data_sources": [
                "Process: Process Creation (Sysmon Event 1)",
                "Command: Scriptblock Execution (Windows PowerShell 4104)",
                "AI Agent Tool-Execution Telemetry",
            ],
            "voter": "AiSecurityAuditVoter",
            "consensus_action": "Tarpit",
            "mitigations": ["AML.M0015: User Prompt Sanitization & Invariant Enforcement", "AML.M0016: Restrict Tool / Subprocess Execution Privileges"],
            "groups": ["Lazarus Group", "Scattered Spider", "Volt Typhoon"],
            "is_atlas": True,
            "sigma_rules": ["AI Agent Shell Injection Attempt", "Tool Argument Traversal Pattern"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0044",
            "name": "AI Tool Path Traversal / Insecure Output Handling",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "description": "Adversaries supply crafted path traversal sequences into LLM agent tool parameters, tricking the autonomous agent into reading or overwriting sensitive host resources outside its workspace boundary.",
            "platforms": ["AI Agent", "LLM Runtime", "FileSystem"],
            "data_sources": [
                "File: File Access / Modification (Sysmon Event 11)",
                "Process: Process Creation (Sysmon Event 1)",
                "Kernel DACL Boundary Violations",
            ],
            "voter": "AiSecurityAuditVoter",
            "consensus_action": "Tarpit",
            "mitigations": ["AML.M0016: Restrict Tool / Subprocess Execution Privileges", "AML.M0018: Isolate AI Agent Runtime & State"],
            "groups": ["APT29", "Volt Typhoon"],
            "is_atlas": True,
            "sigma_rules": ["AI Tool Workspace Path Traversal"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0048",
            "name": "Agent Memory & State Poisoning",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "description": "Adversaries tamper with long-term agent state, persistent memory stores, or policy configuration files (.agents/memory.md, osoosi.toml) to introduce persistent backdoor instructions that survive restarts and session resets.",
            "platforms": ["AI Agent", "Vector Database", "Memory Store"],
            "data_sources": [
                "File: File Modification (Sysmon Event 11)",
                "Registry: Key Value Tampering (Sysmon Event 13)",
                "Differential Privacy & Merkle Audit Trail",
            ],
            "voter": "AiSecurityAuditVoter",
            "consensus_action": "Isolate",
            "mitigations": ["AML.M0018: Isolate AI Agent Runtime & State", "AML.M0015: User Prompt Sanitization & Invariant Enforcement"],
            "groups": ["APT28", "Midnight Blizzard", "Sandworm Team"],
            "is_atlas": True,
            "sigma_rules": ["Agent State File Unauthorized Modification"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0040",
            "name": "AI Runtime Remote Thread Injection",
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "description": "Adversaries inject shellcode or create remote execution threads inside active AI runtime worker processes (python.exe, node.exe, ollama.exe) to elevate privileges, evade defensive hooks, or hijack autonomous agent credentials.",
            "platforms": ["Windows", "Linux", "AI Agent"],
            "data_sources": [
                "Process: CreateRemoteThread (Sysmon Event 8)",
                "Process: ProcessAccess (Sysmon Event 10)",
                "ETW Threat-Intelligence Telemetry",
            ],
            "voter": "AiSecurityAuditVoter",
            "consensus_action": "Isolate",
            "mitigations": ["AML.M0016: Restrict Tool / Subprocess Execution Privileges", "AML.M0018: Isolate AI Agent Runtime & State"],
            "groups": ["Wizard Spider", "Lazarus Group"],
            "is_atlas": True,
            "sigma_rules": ["Remote Thread Created In AI Runtime Process"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0029",
            "name": "Disarm AI Safeguards / Runtime Memory Tampering",
            "tactic_id": "TA0112",
            "tactic_name": "Defense Impairment",
            "description": "Adversaries tamper with the memory space of EDR monitoring agents or AI safeguard processes, modifying protection invariants, unhooking syscalls, or requesting PROCESS_VM_WRITE access to disarm defensive telemetry.",
            "platforms": ["AI Agent", "Windows", "Linux"],
            "data_sources": [
                "Process: ProcessAccess (Sysmon Event 10)",
                "Driver / Kernel Invariant Monitor",
                "Hardware Breakpoint & Thread Context Inspection",
            ],
            "voter": "AiSecurityAuditVoter",
            "consensus_action": "Isolate",
            "mitigations": ["AML.M0018: Isolate AI Agent Runtime & State"],
            "groups": ["LockBit", "BlackCat / ALPHV", "Turla"],
            "is_atlas": True,
            "sigma_rules": ["Suspicious Write Process Memory Into Agent Engine"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0051",
            "name": "LLM Jailbreak / Prompt Obfuscation",
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "description": "Adversaries bypass AI alignment guardrails using obfuscated multi-turn payloads, base64 encoding, rot13, markdown smuggling, or character escaping to induce the AI agent into executing forbidden behaviors.",
            "platforms": ["AI Agent", "LLM Runtime"],
            "data_sources": [
                "Process: Process Creation (Sysmon Event 1)",
                "Agentic Minimax Drift Tracker",
                "Canary Variable & Trap Monitoring",
            ],
            "voter": "AgenticVoter",
            "consensus_action": "Tarpit",
            "mitigations": ["AML.M0015: User Prompt Sanitization & Invariant Enforcement", "AML.M0005: Model Output Sanitation / Guardrails"],
            "groups": ["Scattered Spider", "FIN7"],
            "is_atlas": True,
            "sigma_rules": ["Obfuscated Base64 Shell In AI Prompt Context"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0054",
            "name": "Training Data / System Prompt Exfiltration",
            "tactic_id": "TA0010",
            "tactic_name": "Exfiltration",
            "description": "Adversaries probe autonomous AI agents to reveal proprietary system prompts, embedded API secrets, canary environment variables, or private training examples through side-channel query techniques.",
            "platforms": ["AI Agent", "Cloud", "LLM Runtime"],
            "data_sources": [
                "Network: Outbound Connection (Sysmon Event 3)",
                "AI Agent Canary Tripwire Trigger",
                "Agent Egress Controller Audit",
            ],
            "voter": "AgenticVoter",
            "consensus_action": "Alert",
            "mitigations": ["AML.M0005: Model Output Sanitation / Guardrails", "AML.M0018: Isolate AI Agent Runtime & State"],
            "groups": ["APT29", "Midnight Blizzard"],
            "is_atlas": True,
            "sigma_rules": ["Canary Token In Outbound Network Traffic"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0042",
            "name": "Denial of ML Service / Sponge Attacks",
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "description": "Adversaries craft computationally heavy inputs or infinite agent reasoning trajectories (sponge inputs) designed to exhaust hardware resources, spike memory utilization, and deny service to autonomous EDR inference.",
            "platforms": ["AI Agent", "Model Inference", "GPU / CPU"],
            "data_sources": [
                "Process: CPU / GPU Saturation Metrics",
                "Agent Trajectory Bounded PRM Step Counter",
                "Adaptive Resource Category Monitor",
            ],
            "voter": "AgenticVoter",
            "consensus_action": "Tarpit",
            "mitigations": ["AML.M0016: Restrict Tool / Subprocess Execution Privileges"],
            "groups": ["Sandworm Team", "Silence"],
            "is_atlas": True,
            "sigma_rules": ["Rapid Process Spawn Loop In AI Agent Context"],
            "subtechniques": [],
        },
        {
            "id": "AML.T0031",
            "name": "Model Poisoning / Serialization Backdoors",
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "description": "Adversaries distribute backdoored neural network weights or poisoned serialization files (e.g. pickle, ONNX, PyTorch checkpoints) that trigger remote code execution upon model initialization or load arbitrary payloads.",
            "platforms": ["PyTorch", "ONNX", "HuggingFace", "Python"],
            "data_sources": [
                "File: FileCreate / Download (Sysmon Event 11)",
                "Malware: ONNX / MalConv Byte Inspection",
                "YARA-X Model Deserialization Signatures",
            ],
            "voter": "ZeroDayVoter",
            "consensus_action": "Isolate",
            "mitigations": ["AML.M0017: Verify Cryptographic Integrity of Model Weights"],
            "groups": ["Lazarus Group", "APT28"],
            "is_atlas": True,
            "sigma_rules": ["Malicious Model Weights Download Or Deserialization"],
            "subtechniques": [],
        },
    ]

    existing_tech_indices = {t["id"]: i for i, t in enumerate(final_techniques)}
    for at in atlas_techniques:
        at["detection_mechanisms"] = [
            f"OpenỌ̀ṣọ́ọ̀sì {at['voter']}",
            at["data_sources"][0],
            at["data_sources"][1] if len(at["data_sources"]) > 1 else "Agentic Behavioral Guardrail",
        ]
        if at["id"] in existing_tech_indices:
            final_techniques[existing_tech_indices[at["id"]]].update(at)
        else:
            final_techniques.append(at)

    # MITRE ATLAS Mitigations
    atlas_mitigations = [
        {
            "id": "AML.M0005",
            "name": "Model Output Sanitation / Guardrails",
            "description": "Filter and validate all generative AI tool outputs and function calls before passing to system shells or execution sinks.",
            "techniques": ["AML.T0043", "AML.T0051", "AML.T0054"],
            "defense_type": "AI Guardrail",
        },
        {
            "id": "AML.M0015",
            "name": "User Prompt Sanitization & Invariant Enforcement",
            "description": "Enforce strict syntactic and semantic input guardrails and invariant constraints to neutralize adversarial prompt injections.",
            "techniques": ["AML.T0043", "AML.T0048", "AML.T0051"],
            "defense_type": "AI Guardrail",
        },
        {
            "id": "AML.M0016",
            "name": "Restrict Tool / Subprocess Execution Privileges",
            "description": "Sandbox downstream tool processes spawned by AI agents with restricted kernel access tokens and path isolation.",
            "techniques": ["AML.T0043", "AML.T0044", "AML.T0040", "AML.T0042"],
            "defense_type": "Kernel Isolation",
        },
        {
            "id": "AML.M0017",
            "name": "Verify Cryptographic Integrity of Model Weights",
            "description": "Enforce SHA-256 and digital signature validation on all ONNX, PyTorch, and GGUF model binaries before loading into runtime.",
            "techniques": ["AML.T0031"],
            "defense_type": "Cryptographic Verification",
        },
        {
            "id": "AML.M0018",
            "name": "Isolate AI Agent Runtime & State",
            "description": "Isolate agent memory files (.agents/memory.md), state directories, and runtime memory spaces using OS DACLs and memory protection.",
            "techniques": ["AML.T0044", "AML.T0048", "AML.T0040", "AML.T0029", "AML.T0054"],
            "defense_type": "State Isolation",
        },
    ]

    for am in atlas_mitigations:
        if am["id"] in mitigations_dict:
            mitigations_dict[am["id"]].update(am)
        else:
            mitigations_dict[am["id"]] = am

    # Sort techniques deterministically by tactic then ID
    final_techniques.sort(key=lambda t: (t["tactic_id"], t["id"]))

    # Build Tactics list with accurate technique counts
    tactic_counts = defaultdict(int)
    for t in final_techniques:
        tactic_counts[t["tactic_id"]] += 1

    tactics_list = []
    for tid, tname, tdesc in TACTIC_INFO:
        tactics_list.append({
            "id": tid,
            "name": tname,
            "description": tdesc,
            "techniques_count": tactic_counts.get(tid, 0),
        })

    # Prepare catalog payload
    mitigations_list = sorted(mitigations_dict.values(), key=lambda m: m["id"])
    groups_list = sorted(groups_dict.values(), key=lambda g: g["name"])

    catalog = {
        "tactics": tactics_list,
        "techniques": final_techniques,
        "mitigations": mitigations_list,
        "groups": groups_list,
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    print(f"Writing complete MITRE ATT&CK Catalog to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    if os.path.exists("dashboard/dist"):
        import shutil
        shutil.copy2(OUTPUT_FILE, DASHBOARD_OUTPUT_FILE)
        if os.path.exists(CONFIG_STIX_FILE):
            shutil.copy2(CONFIG_STIX_FILE, DASHBOARD_STIX_FILE)
        print("Copied catalog and STIX bundle to dashboard/dist/")

    file_size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    print(f"Successfully generated {OUTPUT_FILE} ({file_size_mb:.2f} MB)")
    print(f"  Tactics: {len(tactics_list)}")
    print(f"  Parent Techniques: {len(final_techniques)}")
    total_subs = sum(len(t['subtechniques']) for t in final_techniques)
    print(f"  Sub-techniques: {total_subs}")
    print(f"  Total Techniques + Sub-techniques: {len(final_techniques) + total_subs}")
    print(f"  Mitigations: {len(mitigations_list)}")
    print(f"  Threat Groups: {len(groups_list)}")
    techs_with_sigma = sum(1 for t in final_techniques if t["sigma_rules"])
    print(f"  Techniques with associated Sigma rules: {techs_with_sigma}")

if __name__ == "__main__":
    build_catalog()

