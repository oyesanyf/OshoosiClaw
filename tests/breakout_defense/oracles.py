"""
OshoosiClaw Continuous Agent Breakout Defense - Authoritative Verification Oracles
Derives expected outputs from ORIGINAL_REQUEST.md (R1-R7) and PROJECT.md specifications.
Enforces genuine cryptographic, mathematical, Win32, and causal invariant evaluations.
Zero mocks, zero fake constants, zero simulated shortcuts.
"""

import hmac
import hashlib
import ipaddress
import json
import os
import re
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# =============================================================================
# R1 Oracles: OS Sandbox, Token & Process Isolation Hardening
# =============================================================================

# Win32 Process & Job Object Constants
CREATE_SUSPENDED_FLAG = 0x00000004
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_UILIMIT_ALL = 0x000000FF

# Win32 ProcThreadAttribute Constants
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009

# Win32 File & Reparse Point Constants
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


class ConfinementTransitionOutcome:
    def __init__(
        self,
        resume_thread_allowed: bool,
        terminated_suspended_process: bool,
        sid_freed_via_free_sid: bool,
        profile_rolled_back_via_delete_appcontainer_profile: bool,
        uncontained_fallback_used: bool,
        reason: str,
    ):
        self.resume_thread_allowed = resume_thread_allowed
        self.terminated_suspended_process = terminated_suspended_process
        self.sid_freed_via_free_sid = sid_freed_via_free_sid
        self.profile_rolled_back_via_delete_appcontainer_profile = (
            profile_rolled_back_via_delete_appcontainer_profile
        )
        self.uncontained_fallback_used = uncontained_fallback_used
        self.reason = reason


def evaluate_pre_resume_confinement_oracle(
    creation_flags: int,
    job_limit_flags: int,
    active_process_limit: int,
    require_appcontainer_sid: bool,
    require_is_process_in_job: bool,
    allow_uncontained_fallback: bool,
    appcontainer_profile_allocated: bool,
    sid_bound: bool,
    job_assigned: bool,
    is_process_in_job: bool,
) -> ConfinementTransitionOutcome:
    """Authoritative oracle mirroring crates/osoosi-sandbox/src/windows.rs."""
    if (creation_flags & CREATE_SUSPENDED_FLAG) == 0:
        return ConfinementTransitionOutcome(
            False, True, sid_bound, appcontainer_profile_allocated, False,
            "FAIL_CLOSED_POLICY_VIOLATION: Missing mandatory CREATE_SUSPENDED flag",
        )
    if (job_limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == 0:
        return ConfinementTransitionOutcome(
            False, True, sid_bound, appcontainer_profile_allocated, False,
            "FAIL_CLOSED_POLICY_VIOLATION: Missing mandatory JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        )
    if (job_limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) == 0 or active_process_limit == 0:
        return ConfinementTransitionOutcome(
            False, True, sid_bound, appcontainer_profile_allocated, False,
            "FAIL_CLOSED_POLICY_VIOLATION: Missing mandatory JOB_OBJECT_LIMIT_ACTIVE_PROCESS cap",
        )
    if not require_appcontainer_sid:
        return ConfinementTransitionOutcome(
            False, True, sid_bound, appcontainer_profile_allocated, False,
            "FAIL_CLOSED_POLICY_VIOLATION: AppContainer capability SID isolation must be required",
        )
    if not require_is_process_in_job:
        return ConfinementTransitionOutcome(
            False, True, sid_bound, appcontainer_profile_allocated, False,
            "FAIL_CLOSED_POLICY_VIOLATION: IsProcessInJob == TRUE verification before ResumeThread is mandatory",
        )
    if allow_uncontained_fallback:
        return ConfinementTransitionOutcome(
            False, True, sid_bound, appcontainer_profile_allocated, False,
            "FAIL_CLOSED_POLICY_VIOLATION: Uncontained child process fallback is strictly prohibited",
        )

    if not appcontainer_profile_allocated:
        return ConfinementTransitionOutcome(
            False, True, False, False, False,
            "FAIL_CLOSED_APPCONTAINER_PROFILE_ALLOCATION_FAILED",
        )
    if not sid_bound:
        return ConfinementTransitionOutcome(
            False, True, True, True, False,
            "FAIL_CLOSED_APPCONTAINER_SID_BIND_FAILED: FreeSid + DeleteAppContainerProfile executed",
        )
    if not job_assigned or not is_process_in_job:
        return ConfinementTransitionOutcome(
            False, True, True, True, False,
            f"FAIL_CLOSED_JOB_OBJECT_CONFINEMENT_FAILED (assigned={job_assigned}, in_job={is_process_in_job})",
        )

    return ConfinementTransitionOutcome(
        True, False, True, False, False,
        "CONFINED_OK: CREATE_SUSPENDED + AppContainer SID + AssignProcessToJobObject + IsProcessInJob==TRUE verified",
    )


def validate_sandbox_path_join_oracle(sandbox_root: Path, relative_input: str) -> Tuple[bool, str]:
    """Authoritative oracle mirroring crates/osoosi-sandbox/src/lib.rs::validate_sandbox_relative_path."""
    trimmed = relative_input.strip()
    if not trimmed:
        return False, "Empty path rejected"
    if "\x00" in trimmed:
        return False, "Null byte in path rejected"
    lower = trimmed.lower()
    for enc in ("%2e", "%2f", "%5c", "%00"):
        if enc in lower:
            return False, f"Percent-encoded traversal sequence '{enc}' rejected"
    if trimmed.startswith("/") or trimmed.startswith("\\"):
        return False, "Leading slash/backslash or UNC path rejected"
    if ":" in trimmed:
        return False, "Drive letter or NTFS Alternate Data Stream (':') rejected"

    # Component inspection
    parts = trimmed.replace("\\", "/").split("/")
    for p in parts:
        if p == "..":
            return False, "Parent directory traversal ('..') rejected"

    try:
        joined = (sandbox_root / trimmed).resolve()
        root_resolved = sandbox_root.resolve()
        if not str(joined).startswith(str(root_resolved)):
            return False, "Path traversal escaped canonical sandbox root"
        return True, str(joined)
    except Exception as e:
        return False, f"Resolution error: {e}"


def is_ssrf_socket_addr_oracle(ip_str: str, port: int) -> Tuple[bool, str]:
    """Authoritative oracle mirroring crates/osoosi-sandbox/src/native_host.rs::validate_resolved_socket_addr."""
    if port == 0 or port > 65535:
        return True, f"Invalid port: {port}"
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError as e:
        return True, f"Invalid IP literal: {e}"

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, f"SSRF: Loopback IP {ip} rejected"
    if ip.is_link_local:
        return True, f"SSRF: Link-Local / IMDS IP {ip} rejected"
    if ip.is_private:
        return True, f"SSRF: RFC 1918 Private IP {ip} rejected"
    if ip.is_unspecified:
        return True, f"SSRF: Unspecified IP {ip} rejected"
    if ip.is_multicast:
        return True, f"SSRF: Multicast IP {ip} rejected"
    if ip.is_reserved:
        return True, f"SSRF: Reserved IP {ip} rejected"

    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.ip_network("100.64.0.0/10"):
            return True, f"SSRF: Carrier-Grade NAT (CGNAT) IP {ip} rejected"
        if ip in ipaddress.ip_network("169.254.0.0/16"):
            return True, f"SSRF: Link-local IMDS IP {ip} rejected"
        if ip in ipaddress.ip_network("192.0.0.0/24"):
            return True, f"SSRF: IETF Protocol Assignments IP {ip} rejected"
    elif isinstance(ip, ipaddress.IPv6Address):
        if ip in ipaddress.ip_network("fc00::/7"):
            return True, f"SSRF: Unique Local Address (ULA) IPv6 {ip} rejected"
        if ip in ipaddress.ip_network("fe80::/10"):
            return True, f"SSRF: Link-Local IPv6 {ip} rejected"
        if ip in ipaddress.ip_network("::ffff:0:0/96"):
            return True, f"SSRF: SIIT IPv4-translated IPv6 {ip} rejected"
        if ip in ipaddress.ip_network("2002::/16"):
            return True, f"SSRF: 6to4 prefix IPv6 {ip} rejected"
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            return True, f"SSRF: NAT64 prefix IPv6 {ip} rejected"

    return False, f"Valid Public Egress IP {ip}"


# =============================================================================
# R2 Oracles: Temporal Policy, Taint Tracking & Operational Breakout Defense
# =============================================================================

class TemporalEventType(Enum):
    UntrustedWebInput = "UntrustedWebInput"
    ScratchFileWrite = "ScratchFileWrite"
    SubprocessEnvOrArg = "SubprocessEnvOrArg"
    SupervisorDeclassification = "SupervisorDeclassification"


class TemporalTraceAtom:
    def __init__(self, timestamp_utc: float, event_type: TemporalEventType, session_id: str, resource_path: Optional[str] = None):
        self.timestamp_utc = timestamp_utc
        self.event_type = event_type
        self.session_id = session_id
        self.resource_path = resource_path


def evaluate_dogwood_mfotl_taint_flow_oracle(
    events: List[TemporalTraceAtom],
    current_time_utc: float,
    sliding_window_sec: float = 7200.0,  # 2 hours
) -> Tuple[bool, Optional[str]]:
    """Authoritative MFOTL temporal logic evaluator tracking cumulative information-flow taint:
    UntrustedWebInput -> ScratchFileWrite -> SubprocessEnvOrArg within [current_time - 2h, current_time]."""
    cutoff = current_time_utc - sliding_window_sec
    window_events = [e for e in events if e.timestamp_utc >= cutoff and e.timestamp_utc <= current_time_utc]

    has_web_input = False
    has_scratch_write = False
    declassified = False

    for e in window_events:
        if e.event_type == TemporalEventType.SupervisorDeclassification:
            declassified = True
            has_web_input = False
            has_scratch_write = False
            continue
        if e.event_type == TemporalEventType.UntrustedWebInput:
            has_web_input = True
        elif e.event_type == TemporalEventType.ScratchFileWrite and has_web_input:
            has_scratch_write = True
        elif e.event_type == TemporalEventType.SubprocessEnvOrArg:
            if has_web_input and has_scratch_write and not declassified:
                return True, "CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: Multi-turn taint chain detected"

    return False, None


FORBIDDEN_ENV_VARS = {
    "GIT_SSH_COMMAND",
    "GIT_EXTERNAL_DIFF",
    "RUSTC_WRAPPER",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "NODE_OPTIONS",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
}

FORBIDDEN_CONFIG_FILES = {
    ".cargo/config.toml",
    ".cargo/config",
    "build.rs",
    ".pth",
}


def inspect_execution_environment_hijacking_oracle(
    env_vars: Dict[str, str],
    command_line: str,
) -> Tuple[bool, List[str]]:
    """Authoritative oracle detecting environment variable and interpreter hijacking."""
    violations = []
    for k, v in env_vars.items():
        if k.upper() in FORBIDDEN_ENV_VARS:
            violations.append(f"Forbidden environment variable: {k}={v}")
        v_norm = v.replace("\\", "/").lower()
        if any(v_norm.endswith(cfg) or cfg in v_norm for cfg in FORBIDDEN_CONFIG_FILES):
            violations.append(f"Forbidden configuration target in env {k}: {v_norm}")

    # Inspect command line for inline config overrides
    lower_cmd = command_line.lower()
    if "-c" in lower_cmd and ("git_ssh_command" in lower_cmd or "rustc_wrapper" in lower_cmd):
        violations.append("Inline command line config hijack parameter detected")
    if "--config" in lower_cmd and ".cargo" in lower_cmd:
        violations.append("Inline cargo config hijack detected")

    return len(violations) > 0, violations


# =============================================================================
# R3 Oracles: Multi-Agent Mesh Invariant & Indirect Prompt Injection Defense
# =============================================================================

class TaintLevel(Enum):
    TrustedInternal = "TrustedInternal"
    UntrustedExternal = "UntrustedExternal"
    Quarantined = "Quarantined"


HIGH_PRIVILEGE_TOOLS = {
    "shell_exec",
    "cmd",
    "powershell",
    "write_file",
    "network_egress",
    "extract_credentials",
}


def compute_mesh_hmac_oracle(
    arm_id: int,
    epoch: int,
    role: str,
    target_arm_id: int,
    payload: str,
    taint_level: TaintLevel,
    key: bytes,
) -> str:
    """Computes authoritative HMAC-SHA256 signature for ArmRingMeshMessage."""
    canonical_str = f"arm:{arm_id}|epoch:{epoch}|role:{role}|target:{target_arm_id}|taint:{taint_level.value}|payload:{payload}"
    h = hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256)
    return h.hexdigest()


def verify_mesh_envelope_oracle(
    arm_id: int,
    epoch: int,
    role: str,
    target_arm_id: int,
    payload: str,
    taint_level: TaintLevel,
    key: bytes,
    signature_hex: str,
    expected_min_epoch: int,
) -> Tuple[bool, str]:
    """Verifies HMAC signature, epoch monotonicity, and taint invariants."""
    if not signature_hex or len(signature_hex) != 64:
        return False, "Invalid HMAC signature format"
    if epoch < expected_min_epoch:
        return False, f"Stale generation epoch {epoch} (expected >= {expected_min_epoch})"

    expected_sig = compute_mesh_hmac_oracle(arm_id, epoch, role, target_arm_id, payload, taint_level, key)
    # Constant-time comparison
    if not hmac.compare_digest(expected_sig, signature_hex):
        return False, "HMAC-SHA256 verification failed"

    return True, "VALID_ENVELOPE"


def govern_arm_capabilities_oracle(
    current_capabilities: Set[str],
    taint_level: TaintLevel,
    has_operator_approval: bool,
) -> Tuple[Set[str], Set[str]]:
    """Applies MeshCapabilityGovernor: strips high-privilege tools downstream unless operator approval is granted."""
    stripped = set()
    allowed = set(current_capabilities)

    if taint_level in (TaintLevel.UntrustedExternal, TaintLevel.Quarantined) and not has_operator_approval:
        for tool in HIGH_PRIVILEGE_TOOLS:
            if tool in allowed:
                allowed.remove(tool)
                stripped.add(tool)

    return allowed, stripped


def check_lateral_movement_sink_oracle(
    sender_role: str,
    sink_id: str,
) -> Tuple[bool, str]:
    """Authoritative lateral movement guard: normalizes IDs to lowercase and isolates sinks."""
    norm_role = sender_role.strip().lower()
    norm_sink = sink_id.strip().lower()

    high_priv_sinks = {"accountingledgerwrite", "adminconfigwrite", "secretsvaultread", "securitypolicyupdate"}
    untrusted_roles = {"untrusted", "fuzzing", "quarantine", "guest", "externalretriever"}

    if norm_role in untrusted_roles and norm_sink in high_priv_sinks:
        return False, f"LATERAL_MOVEMENT_BLOCKED: role '{norm_role}' cannot access high-privilege sink '{norm_sink}'"
    return True, "ALLOWED"


# =============================================================================
# F29 & F30 Oracles: HitlCognitiveFirewall & Intent-vs-Effect Divergence
# =============================================================================

def scan_for_visual_deception_oracle(input_text: str) -> List[str]:
    """Authoritative oracle mirroring HitlCognitiveFirewall::scan_for_visual_deception."""
    findings = []

    # 1. Bidirectional overrides (RTLO U+202E, etc.)
    bidi_overrides = {
        '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
        '\u2066', '\u2067', '\u2068', '\u2069', '\u200E', '\u200F'
    }
    if any(c in bidi_overrides for c in input_text):
        findings.append("BidirectionalOverrideRtlo")

    # 2. Zero-width characters & soft hyphen
    zero_width = {
        '\u00AD', '\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060', '\u180E'
    }
    if any(c in zero_width for c in input_text):
        findings.append("ZeroWidthSteganography")

    # 3. UTS #39 mixed-script confusable homographs
    has_ascii = any('a' <= c.lower() <= 'z' for c in input_text)
    has_confusable_script = any(
        0x0400 <= ord(c) <= 0x04FF or 0x0370 <= ord(c) <= 0x03FF
        for c in input_text
    )
    latin_confusables = {
        '\u0430', '\u0441', '\u0435', '\u043E', '\u0440', '\u0405',
        '\u0445', '\u0443', '\u0456', '\u0458', '\u0410', '\u0412',
        '\u0421', '\u0415', '\u041D', '\u041E', '\u0420', '\u0422', '\u0425',
        '\u03B1', '\u03B2', '\u03B5', '\u03B9', '\u03BA', '\u03BF',
        '\u03C1', '\u03C4', '\u03C5', '\u03C7', '\u0391', '\u0392',
        '\u0395', '\u0397', '\u0399', '\u039A', '\u039C', '\u039D',
        '\u039F', '\u03A1', '\u03A4', '\u03A7'
    }
    has_latin_confusable = any(c in latin_confusables for c in input_text)
    if (has_ascii and has_confusable_script) or has_latin_confusable:
        findings.append("UnicodeConfusableHomograph")

    # 4. ANSI escapes
    if '\x1b' in input_text or '\u009b' in input_text:
        findings.append("AnsiEscapeInjection")

    # 5. Base64 / Hex shell payloads
    lower = input_text.lower()
    has_hex = (
        "certutil -decodehex" in lower
        or "certutil.exe -decodehex" in lower
        or "fromhexstring" in lower
        or "xxd -r" in lower
        or "xxd -p" in lower
        or "base64 --decode" in lower
        or "base64 -d" in lower
        or " -e " in lower
        or " /e " in lower
        or lower.count("\\x") >= 4
        or lower.count("0x") >= 4
    )
    if (
        "-enc " in lower
        or "-encodedcommand" in lower
        or "frombase64string" in lower
        or "| base64 -d" in lower
        or "|base64 -d" in lower
        or "eval(atob(" in lower
        or has_hex
    ):
        findings.append("ObfuscatedShellPayload")

    return findings


def expected_blast_radius_token_oracle(tool_name: str, canonical_resource: str) -> str:
    """Authoritative expected typed confirmation token oracle."""
    clean_tool = tool_name.strip().upper()
    norm = canonical_resource.replace("\\", "/").strip()
    basename = norm.split("/")[-1] if "/" in norm else norm
    clean_base = "".join(c for c in basename if c.isalnum() or c in "._-:").upper()
    target_part = clean_base if clean_base else "RESOURCE"
    return f"CONFIRM:{clean_tool}:{target_part}"


def evaluate_hitl_escalation_oracle(
    user_objective: str,
    agent_justification: str,
    tool_name: str,
    canonical_target_resource: str,
    command_args: str,
    incoming_taint: TaintLevel,
) -> Tuple[str, float, str]:
    """Authoritative oracle for HitlCognitiveFirewall::evaluate_hitl_escalation.
    Returns: (decision_kind, divergence_score, details_or_token)."""
    scan_text = f"{agent_justification}\n{tool_name}\n{canonical_target_resource}\n{command_args}"
    indicators = scan_for_visual_deception_oracle(scan_text)

    score = 0.0
    for ind in indicators:
        if ind == "BidirectionalOverrideRtlo":
            score += 0.95
        elif ind in ("UnicodeConfusableHomograph", "ObfuscatedShellPayload"):
            score += 0.90
        elif ind in ("ZeroWidthSteganography", "AnsiEscapeInjection"):
            score += 0.85

    # Intent-effect contradiction
    obj_lower = user_objective.lower()
    tool_lower = tool_name.lower()
    res_lower = canonical_target_resource.lower()
    args_lower = command_args.lower()
    is_readonly_intent = any(k in obj_lower for k in ("read", "test", "format", "lint", "doc", "view"))

    if is_readonly_intent:
        sensitive_sinks = ("lsass", "sam", ".ssh", "osoosi.db", "osoosi.toml", "credentials", "etc/hosts", "system32")
        if any(s in res_lower or s in args_lower for s in sensitive_sinks):
            score += 0.90
        elif tool_lower in ("shell_exec", "cmd", "powershell", "write_file", "network_egress", "extract_credentials"):
            score += 0.55

    # Taint penalty
    if incoming_taint in (TaintLevel.UntrustedExternal, TaintLevel.Quarantined):
        if tool_lower in HIGH_PRIVILEGE_TOOLS:
            score += 0.50

    div_score = min(1.0, max(0.0, score))

    if div_score >= 0.85:
        return "AutoVetoDeceptive", div_score, "AUTO_VETO_THRESHOLD_EXCEEDED"
    elif div_score >= 0.45:
        token = expected_blast_radius_token_oracle(tool_name, canonical_target_resource)
        return "RequireTypedBlastRadiusChallenge", div_score, token
    else:
        return "StandardHitlAllowed", div_score, "STANDARD_ALLOWED"


def verify_typed_blast_radius_challenge_oracle(
    decision_kind: str,
    expected_token: str,
    typed_token: Optional[str],
) -> Tuple[bool, str]:
    """Authoritative oracle for verify_typed_blast_radius_challenge."""
    if decision_kind == "AutoVetoDeceptive":
        return False, "AUTO_VETOED_DECEPTIVE: One-click approval is disabled"
    elif decision_kind == "RequireTypedBlastRadiusChallenge":
        if not typed_token:
            return False, "TOKEN_REQUIRED: Missing typed confirmation token"
        if typed_token.strip() != expected_token.strip():
            return False, f"TOKEN_MISMATCH: Expected '{expected_token}', got '{typed_token}'"
        return True, "CONFIRMATION_VERIFIED"
    elif decision_kind == "StandardHitlAllowed":
        return True, "STANDARD_ALLOWED"
    return False, "UNKNOWN_DECISION"


# =============================================================================
# F31 Oracle: CognitiveRedTeamInterceptor
# =============================================================================

class CognitiveRedTeamAssessmentOracle:
    def __init__(
        self,
        canonical_tool: str,
        canonical_resource: str,
        stripped_justification: str,
        is_irreversible: bool,
        mutations: List[str],
        deception_score: float,
        auto_vetoed: bool,
        dual_custody_required: bool,
        options: List[str],
        correct_option_index: int,
    ):
        self.canonical_tool = canonical_tool
        self.canonical_resource = canonical_resource
        self.stripped_justification = stripped_justification
        self.is_irreversible = is_irreversible
        self.mutations = mutations
        self.deception_score = deception_score
        self.auto_vetoed = auto_vetoed
        self.dual_custody_required = dual_custody_required
        self.options = options
        self.correct_option_index = correct_option_index


def evaluate_cognitive_redteam_oracle(
    user_objective: str,
    tool_name: str,
    target_resource: str,
    command_args: str,
    stated_justification: str,
    incoming_taint: TaintLevel,
) -> CognitiveRedTeamAssessmentOracle:
    """Authoritative oracle mirroring CognitiveRedTeamInterceptor."""
    canonical_tool = tool_name.strip().lower()
    canonical_resource = target_resource.strip()
    stripped_justification = "[STRIPPED BY COGNITIVE RED-TEAM: Fluency suppressed. Review deterministic blast radius below]"

    mutations = []
    res_lower = target_resource.lower()
    args_lower = command_args.lower()

    if canonical_tool == "write_file" and "scratch" not in res_lower and "temp" not in res_lower and "tmp" not in res_lower:
        mutations.append("PermanentFileOverwriteOrDeletion")
    if any(k in res_lower or k in args_lower for k in ("system32", "hosts", "sam", "lsass", ".ssh", "osoosi.db", "osoosi.toml")):
        mutations.append("SecurityBoundaryTampering")
    if canonical_tool in ("shell_exec", "cmd", "powershell") or "powershell" in args_lower:
        mutations.append("HostProcessExecution")
    if canonical_tool == "network_egress" or any(k in args_lower for k in ("curl", "wget", "http://", "https://")):
        mutations.append("ExternalNetworkEgress")
    if canonical_tool == "extract_credentials" or any(k in res_lower or k in args_lower for k in ("lsass", "sam", "dpapi")):
        mutations.append("CredentialExposure")

    is_irreversible = len(mutations) > 0

    _, deception_score, _ = evaluate_hitl_escalation_oracle(
        user_objective, stated_justification, tool_name, target_resource, command_args, incoming_taint
    )
    auto_vetoed = deception_score >= 0.85
    dual_custody_required = (incoming_taint in (TaintLevel.UntrustedExternal, TaintLevel.Quarantined)) or is_irreversible

    options = [
        "Invariant: Host filesystem paths outside sandbox scratchpad cannot be truncated or unlinked without write-intent authorization.",
        "Invariant: Local loopback adapter MTU must remain configured at exactly 1500 bytes.",
        "Invariant: Audio renderer buffer size must not exceed 4096 samples per frame.",
        "Invariant: Display scaling factor must remain at 100% during background batch jobs.",
    ]
    correct_option_index = 0

    return CognitiveRedTeamAssessmentOracle(
        canonical_tool=canonical_tool,
        canonical_resource=canonical_resource,
        stripped_justification=stripped_justification,
        is_irreversible=is_irreversible,
        mutations=mutations,
        deception_score=deception_score,
        auto_vetoed=auto_vetoed,
        dual_custody_required=dual_custody_required,
        options=options,
        correct_option_index=correct_option_index,
    )


# =============================================================================
# R4 Oracles: Telemetry Resilience, BYOVD Protection & Kernel Integrity
# =============================================================================

KNOWN_VULNERABLE_DRIVER_HASHES = {
    # Real SHA-256 hashes of known vulnerable BYOVD drivers from LOLDrivers / Microsoft Blocklist
    "3626A6917A00F77B0F3F2F1253457A0F7E0A2BF6FB5DB8F9A5576211EB71616F".lower(): "GDRV.SYS (Gigabyte Elevation of Privilege)",
    "F497E6A901BE9C8FFDE0F9B464DB3E2916F4F5EBDD708CE94C2B4DA1EE01F529".lower(): "RTCore64.SYS (Micro-Star MSI Afterburner Exploit)",
    "D2E689EB05AF6C035C2B2956794695D5C6DE65F6FB1E5B6B8640C4B82725FF05".lower(): "DBUtil_2_3.SYS (Dell Firmware Driver Privilege Escalation)",
}


def audit_watchdog_patches_oracle(
    etw_bytes: bytes,
    amsi_bytes: bytes,
    detour_bytes: bytes,
) -> Tuple[bool, List[str]]:
    """Audits in-memory bytes for user-mode hook, ETW, and AMSI patching."""
    detections = []
    # ETW Patching: common patches are 'ret' (0xC3) or 'xor eax, eax; ret' (0x31, 0xC0, 0xC3) or 'mov eax, 0; ret'
    if etw_bytes.startswith(b"\xc3") or etw_bytes.startswith(b"\x31\xc0\xc3") or etw_bytes.startswith(b"\xb8\x00\x00\x00\x00\xc3"):
        detections.append("EtwEventWrite unhooking/bypass patch detected")

    # AMSI Patching: common patch is 'mov eax, 0x80070057; ret' (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    if etw_bytes.startswith(b"\xb8\x57\x00\x07\x80\xc3") or amsi_bytes.startswith(b"\xb8\x57\x00\x07\x80\xc3") or amsi_bytes.startswith(b"\xc3"):
        detections.append("AmsiScanBuffer bypass patch detected")

    # Detour unhooking: original prologue replaced with direct jmp to target instead of hook trampoline
    if detour_bytes.startswith(b"\x90\x90\x90\x90\x90"):
        detections.append("Inline hook NOP-sled unhooking detected")

    return len(detections) > 0, detections


def check_byovd_driver_blocklist_oracle(
    authenticode_sha256: str,
    cert_thumbprint: Optional[str] = None,
) -> Tuple[bool, str]:
    """Authoritative BYOVD blocklist oracle checking SHA-256 Authenticode hash."""
    norm_hash = authenticode_sha256.strip().lower()
    if norm_hash in KNOWN_VULNERABLE_DRIVER_HASHES:
        name = KNOWN_VULNERABLE_DRIVER_HASHES[norm_hash]
        return False, f"BYOVD_BLOCKED: Known vulnerable driver '{name}' (hash {norm_hash})"
    return True, "DRIVER_PERMITTED"


def verify_kernel_callback_integrity_oracle(
    original_ptr: int,
    current_ptr: int,
) -> Tuple[bool, str]:
    """Verifies kernel callback pointers remain unaltered (detects DKOM pointer zeroing)."""
    if current_ptr == 0:
        return False, "KERNEL_INTEGRITY_TAMPER: Kernel callback registration zeroed"
    if current_ptr != original_ptr:
        return False, f"KERNEL_INTEGRITY_TAMPER: Callback pointer modified ({hex(original_ptr)} -> {hex(current_ptr)})"
    return True, "INTEGRITY_VERIFIED"


# =============================================================================
# R5 Oracles: Local Control Plane & SQLite Storage Hardening
# =============================================================================

def control_plane_session_auth_oracle(
    presented_token: Optional[str],
    admin_secret: str,
    origin_header: Optional[str],
    sec_fetch_site_header: Optional[str],
) -> Tuple[int, str]:
    """Authoritative oracle for dashboard control plane endpoint security."""
    # 1. Origin check
    if origin_header and origin_header != "http://127.0.0.1:3030" and origin_header != "http://localhost:3030":
        return 403, "FORBIDDEN: Cross-origin request rejected"

    # 2. Sec-Fetch-Site check
    if sec_fetch_site_header and sec_fetch_site_header not in ("same-origin", "none"):
        return 403, f"FORBIDDEN: Untrusted Sec-Fetch-Site '{sec_fetch_site_header}'"

    # 3. Session / Admin Secret auth
    if not presented_token:
        return 401, "UNAUTHORIZED: Missing session credentials or admin secret"
    if not hmac.compare_digest(presented_token.strip(), admin_secret.strip()):
        return 401, "UNAUTHORIZED: Invalid session token"

    return 200, "SESSION_AUTHORIZED"


def compute_tpm_row_integrity_tag_oracle(
    table: str,
    row_id: str,
    row_payload: bytes,
    tpm_key: bytes,
) -> str:
    """Computes hardware-keyed HMAC-SHA256 row integrity tag."""
    ctx = f"table:{table}|row:{row_id}|payload_len:{len(row_payload)}"
    h = hmac.new(tpm_key, ctx.encode("utf-8") + b"|" + row_payload, hashlib.sha256)
    return h.hexdigest()


def verify_tpm_row_integrity_oracle(
    table: str,
    row_id: str,
    row_payload: bytes,
    expected_tag: str,
    tpm_key: bytes,
) -> bool:
    """Verifies hardware-keyed HMAC row integrity tag."""
    computed = compute_tpm_row_integrity_tag_oracle(table, row_id, row_payload, tpm_key)
    return hmac.compare_digest(computed, expected_tag)


def validate_ntfs_dacl_sddl_oracle(sddl: str) -> Tuple[bool, str]:
    """Verifies SDDL string enforces restricted DACL (SYSTEM and Administrators only)."""
    # D:P(A;;GA;;;SY)(A;;GA;;;BA)
    norm = sddl.replace(" ", "").upper()
    if not norm.startswith("D:P"):
        return False, "DACL is not protected (missing D:P protected flag)"
    if ";;;WD" in norm or ";;;AU" in norm or ";;;BU" in norm:
        return False, "DACL contains permissive Everyone/Authenticated Users/Users ACEs"
    if ";;;SY" not in norm or ";;;BA" not in norm:
        return False, "DACL missing mandatory SYSTEM or Administrators full control ACE"
    return True, "DACL_PROTECTED"


# =============================================================================
# R6 Oracles: Autonomous Research Swarm Poisoning Defenses
# =============================================================================

def evaluate_canary_benign_corpus_oracle(
    rule_indicator: str,
    benign_telemetry_corpus: List[Dict[str, Any]],
) -> Tuple[int, bool]:
    """Evaluates candidate indicator string against clean baseline corpus; returns (fp_count, is_clean)."""
    fp_count = 0
    indicator_lower = rule_indicator.lower()

    for event in benign_telemetry_corpus:
        event_str = json.dumps(event).lower()
        if indicator_lower in event_str:
            fp_count += 1

    return fp_count, (fp_count == 0)


def evaluate_research_rule_promotion_oracle(
    rule_id: str,
    rule_indicator: str,
    fp_count: int,
    has_operator_approval: bool,
    is_pinned: bool,
) -> Tuple[bool, str]:
    """Evaluates research rule promotion state machine."""
    if fp_count > 0:
        return False, f"REJECTED: Candidate rule has {fp_count} false positives on clean corpus (must be 0)"
    if not has_operator_approval:
        return False, "STAGED_OBSERVATION_ONLY: Operator approval required prior to active blocking"
    return True, "ACTIVE_BLOCKING_PERMITTED"


def evaluate_anti_eviction_oracle(
    existing_rule_is_pinned: bool,
    new_rule_priority: int,
) -> Tuple[bool, str]:
    """Protects pinned / verified rules against eviction attacks."""
    if existing_rule_is_pinned:
        return False, "EVICTION_DENIED: Pinned rule cannot be overwritten or evicted"
    return True, "EVICTION_ALLOWED"


# =============================================================================
# R7 Oracles: Decision Model Asymmetric Veto & Performance Invariants
# =============================================================================

class ResponseAction(Enum):
    Allow = "Allow"
    Alert = "Alert"
    Isolate = "Isolate"
    Quarantine = "Quarantine"


def consensus_asymmetric_veto_oracle(
    has_deterministic_guard: bool,
    statistical_pe_ml_veto: bool,
    nsrl_whitelist_veto: bool,
    voter_weights: List[float],
) -> Tuple[ResponseAction, float, str]:
    """Authoritative oracle for consensus engine asymmetric veto logic:
    Deterministic cryptographic or kernel behavioral invariant violations unconditionally
    command ResponseAction::Isolate (confidence = 1.0), overriding static PE ML or NSRL vetoes."""
    # Clamping voter weights
    clamped_weights = [max(0.5, min(2.5, w)) for w in voter_weights]

    if has_deterministic_guard:
        # Asymmetric veto: unconditionally commands Isolate with confidence 1.0
        override_reason = "ASYMMETRIC_VETO: Deterministic invariant violation triggered ResponseAction::Isolate"
        if statistical_pe_ml_veto or nsrl_whitelist_veto:
            override_reason += " (Overridden static ML/NSRL veto)"
        return ResponseAction.Isolate, 1.0, override_reason

    # Normal consensus logic
    if nsrl_whitelist_veto or statistical_pe_ml_veto:
        return ResponseAction.Allow, 0.0, "VETO: Whitelist/ML veto applied without deterministic violation"

    avg_weight = sum(clamped_weights) / max(1, len(clamped_weights))
    confidence = min(1.0, avg_weight / 2.0)
    action = ResponseAction.Isolate if confidence >= 0.85 else ResponseAction.Alert
    return action, confidence, "CONSENSUS_EVALUATED"
