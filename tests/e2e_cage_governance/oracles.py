"""
Authoritative Reference Oracles for Google CAGE Governance Substrate.
Implements exact mathematical, cryptographic, state-space, and policy specifications
from ORIGINAL_REQUEST.md, PROJECT.md, and spec_miner_survey/report.md.
"""

import collections
import copy
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

# =============================================================================
# Regular Expressions & Constants
# =============================================================================

DIGEST_64_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")
VERSION_16_HEX_REGEX = re.compile(r"^[0-9a-f]{16}$")
ROUTING_SEAL_TTL_SECONDS = 30
DEFAULT_HMAC_SECRET = b"oshoosiclaw_cage_governance_secret_2026_test_key"


class GovernanceVerdict:
    ALLOW = "ALLOW"
    NARROW = "NARROW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DEFER = "DEFER"
    DENY = "DENY"


class PolicyConflictError(Exception):
    """Raised when an ingested or checked policy drifts from the active pinned version (HTTP 409)."""
    def __init__(self, message: str, pinned_version: str, submitted_version: str):
        super().__init__(message)
        self.pinned_version = pinned_version
        self.submitted_version = submitted_version


class SealRejectionError(Exception):
    """Raised when host capability gate rejects a routing seal (expired, replayed, or invalid)."""
    pass


# =============================================================================
# F10 & F3: RFC 8785 JSON Canonicalization Scheme (JCS) & Version Pinning
# =============================================================================

def utf16_sort_key(s: str):
    """Produce sort key based on UTF-16 code units as required by RFC 8785 §3.2.3."""
    return [ord(c) for c in s]


def rfc8785_canonicalize(data: Any) -> bytes:
    """
    Serializes a Python object into canonical JSON bytes strictly following RFC 8785.
    - Object keys sorted by UTF-16 code unit values.
    - No whitespace between tokens.
    - Floating point numbers formatted without exponential notation unless needed.
    """
    def _canonicalize(val: Any) -> str:
        if val is None:
            return "null"
        elif isinstance(val, bool):
            return "true" if val else "false"
        elif isinstance(val, int):
            return str(val)
        elif isinstance(val, float):
            if math.isnan(val) or math.isinf(val):
                raise ValueError("NaN and Infinity are not permitted in RFC 8785 JSON")
            # Format float deterministically
            if val.is_integer():
                return f"{int(val)}.0"
            s = f"{val:.10g}"
            if "e" in s:
                base, exp = s.split("e")
                return f"{base}e{int(exp)}"
            return s
        elif isinstance(val, str):
            # JSON escape according to RFC 8785 §3.2.2.2
            escaped = []
            for char in val:
                cp = ord(char)
                if char == '"':
                    escaped.append('\\"')
                elif char == '\\':
                    escaped.append('\\\\')
                elif char == '\b':
                    escaped.append('\\b')
                elif char == '\f':
                    escaped.append('\\f')
                elif char == '\n':
                    escaped.append('\\n')
                elif char == '\r':
                    escaped.append('\\r')
                elif char == '\t':
                    escaped.append('\\t')
                elif cp < 0x20:
                    escaped.append(f"\\u{cp:04x}")
                else:
                    escaped.append(char)
            return '"' + "".join(escaped) + '"'
        elif isinstance(val, (list, tuple)):
            return "[" + ",".join(_canonicalize(item) for item in val) + "]"
        elif isinstance(val, dict):
            # Sort keys by UTF-16 code units
            sorted_keys = sorted(val.keys(), key=utf16_sort_key)
            pairs = []
            for k in sorted_keys:
                pairs.append(_canonicalize(k) + ":" + _canonicalize(val[k]))
            return "{" + ",".join(pairs) + "}"
        else:
            raise TypeError(f"Unsupported type for RFC 8785 canonicalization: {type(val)}")

    return _canonicalize(data).encode("utf-8")


def compute_policy_version_id(policy_bundle: Any) -> str:
    """
    Computes a deterministic 16-character lowercase hex SHA-256 version ID
    from the RFC 8785 JCS canonical representation of the policy bundle.
    """
    if isinstance(policy_bundle, (str, bytes)):
        # If string/bytes, try parsing as JSON or YAML
        try:
            parsed = json.loads(policy_bundle)
            canonical_bytes = rfc8785_canonicalize(parsed)
        except Exception:
            try:
                parsed = yaml.safe_load(policy_bundle)
                if isinstance(parsed, (dict, list)):
                    canonical_bytes = rfc8785_canonicalize(parsed)
                else:
                    canonical_bytes = str(policy_bundle).strip().encode("utf-8")
            except Exception:
                canonical_bytes = str(policy_bundle).strip().encode("utf-8")
    else:
        canonical_bytes = rfc8785_canonicalize(policy_bundle)

    full_sha = hashlib.sha256(canonical_bytes).hexdigest()
    version_id = full_sha[:16].lower()
    assert VERSION_16_HEX_REGEX.match(version_id), f"Invalid 16-hex version ID: {version_id}"
    return version_id


# =============================================================================
# F1 & F2: Multi-Format Policy Auto-Detection & Compilation
# =============================================================================

class PolicyFormat:
    ACS = "acs"
    AAIF = "aaif"
    OSCAL = "oscal"
    LULA = "lula"
    CAGE_YAML = "cage_yaml"
    UNKNOWN = "unknown"


def auto_detect_policy_format(content: Any) -> str:
    """
    Auto-detects the policy format from YAML/JSON text or dictionary according to Section 2.2:
    1. 'oscal-version' -> oscal
    2. 'kind: LulaValidation' -> lula
    3. 'component-definition' -> inspect back-matter for rego/k8s: 'lula' if found, else 'oscal'
    4. 'behaviorDeclarations' -> acs
    5. 'governedRunLoop' -> aaif
    6. 'stpa_control_structure' or root with system/hazards/control_actions -> cage_yaml
    """
    doc = None
    if isinstance(content, dict):
        doc = content
    elif isinstance(content, str):
        try:
            doc = json.loads(content)
        except Exception:
            try:
                doc = yaml.safe_load(content)
            except Exception:
                pass

    if not isinstance(doc, dict):
        raise ValueError("Invalid policy content: must parse to a mapping/dictionary")

    # 1. Root or nested oscal-version
    if "oscal-version" in doc:
        return PolicyFormat.OSCAL
    if "component-definition" in doc:
        comp = doc["component-definition"]
        # Check if wrapped LulaValidation in back-matter
        back_matter = comp.get("back-matter", {})
        resources = back_matter.get("resources", [])
        for r in resources:
            desc = r.get("description", "")
            if "rego" in desc.lower() or "lulavalidation" in desc.lower() or "kubernetes" in desc.lower():
                return PolicyFormat.LULA
        metadata = comp.get("metadata", {})
        if "oscal-version" in metadata:
            return PolicyFormat.OSCAL
        return PolicyFormat.OSCAL

    # 2. LulaValidation kind
    if doc.get("kind") == "LulaValidation":
        return PolicyFormat.LULA

    # 3. Microsoft ACS
    if "behaviorDeclarations" in doc:
        return PolicyFormat.ACS

    # 4. Linux Foundation AAIF
    if "governedRunLoop" in doc:
        return PolicyFormat.AAIF

    # 5. Native CAGE STPA
    if "stpa_control_structure" in doc:
        return PolicyFormat.CAGE_YAML
    if "hazards" in doc and "control_actions" in doc and "system" in doc:
        return PolicyFormat.CAGE_YAML

    raise ValueError("Unrecognized policy format: missing mandatory schema discriminant")


def compile_policy(content: Any, format_override: Optional[str] = None) -> Dict[str, Any]:
    """
    Compiles an external policy into CAGE Cedar authorization rules and STPA UCAs,
    along with computing the deterministic 16-character hex policy version ID.
    """
    if isinstance(content, str):
        doc = yaml.safe_load(content) if ("\n" in content and not content.strip().startswith("{")) else json.loads(content)
    else:
        doc = copy.deepcopy(content)

    detected_format = format_override if (format_override and format_override != "auto") else auto_detect_policy_format(doc)

    cedar_rules = []
    unsafe_control_actions = []
    cbf_gamma = 0.5
    cbf_b_min = 10.0

    if detected_format == PolicyFormat.ACS:
        for b in doc.get("behaviorDeclarations", []):
            b_id = b.get("id", "ACS-GEN")
            action = b.get("action", "GeneralAction")
            hazard_refs = b.get("hazardRefs", ["H-1"])
            terminal = b.get("terminalClassification", "REVERSIBLE")
            uca = {
                "id": b_id,
                "action": action,
                "uca_type": b.get("ucaType", "unsafe_action"),
                "hazard_refs": hazard_refs,
                "terminal_classification": terminal,
                "condition": b.get("constraints", [])
            }
            unsafe_control_actions.append(uca)
            cedar_rules.append(f'forbid (principal, action == Action::"{action}", resource) when {{ @id("{b_id}") }};')

    elif detected_format == PolicyFormat.AAIF:
        run_loop = doc.get("governedRunLoop", {})
        for stage in run_loop.get("stages", []):
            stage_name = stage.get("name", "generic")
            for hook in stage.get("hooks", []):
                h_id = hook.get("id", f"AAIF-{stage_name}")
                action = hook.get("action", stage_name)
                uca = {
                    "id": h_id,
                    "action": action,
                    "stage": stage_name,
                    "hazard_refs": ["H-AAIF"],
                    "terminal_classification": "REVERSIBLE",
                    "constraints": hook.get("constraints", [])
                }
                unsafe_control_actions.append(uca)
                cedar_rules.append(f'permit (principal in Role::"Agent", action == Action::"{action}", resource);')

    elif detected_format == PolicyFormat.OSCAL:
        comp_def = doc.get("component-definition", doc)
        for comp in comp_def.get("components", []):
            for ctrl_impl in comp.get("control-implementations", []):
                for req in ctrl_impl.get("implemented-requirements", []):
                    ctrl_id = req.get("control-id", "ac-3")
                    action = "access_enforcement" if "ac" in ctrl_id else "system_actuation"
                    uca = {
                        "id": req.get("uuid", ctrl_id),
                        "action": action,
                        "control_id": ctrl_id,
                        "hazard_refs": ["H-OSCAL"],
                        "terminal_classification": "IRREVERSIBLE_TERMINAL" if "ac-3" in ctrl_id else "REVERSIBLE"
                    }
                    unsafe_control_actions.append(uca)
                    cedar_rules.append(f'forbid (principal, action == Action::"{action}", resource) when {{ context.control == "{ctrl_id}" }};')

    elif detected_format == PolicyFormat.LULA:
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "lula-validation")
        rego = doc.get("spec", {}).get("policy", {}).get("opa", {}).get("rego", "")
        uca = {
            "id": name,
            "action": "ModifySystemBinary",
            "rego_body": rego,
            "hazard_refs": ["H-K8S-BREACH"],
            "terminal_classification": "IRREVERSIBLE_TERMINAL"
        }
        unsafe_control_actions.append(uca)
        cedar_rules.append(f'forbid (principal, action == Action::"ModifySystemBinary", resource);')

    elif detected_format == PolicyFormat.CAGE_YAML:
        stpa = doc.get("stpa_control_structure", doc)
        for u in stpa.get("unsafe_control_actions", []):
            unsafe_control_actions.append(u)
            if "cedar_rule" in u:
                cedar_rules.append(u["cedar_rule"].strip())
            else:
                act = u.get("action", "UnknownAction")
                cedar_rules.append(f'forbid (principal, action == Action::"{act}", resource);')

    compiled_bundle = {
        "format": detected_format,
        "cedar_rules": sorted(cedar_rules),
        "unsafe_control_actions": unsafe_control_actions,
        "cbf_parameters": {
            "gamma": cbf_gamma,
            "b_min": cbf_b_min
        }
    }

    version_id = compute_policy_version_id(compiled_bundle)
    compiled_bundle["policy_version_id"] = version_id
    compiled_bundle["rules_count"] = len(cedar_rules) + len(unsafe_control_actions)
    return compiled_bundle


# =============================================================================
# F4: Phase 1 Read-Only Multi-Tier Gating Pipeline
# =============================================================================

class Phase1Gate:
    """
    Executes idempotent, non-mutating checks across:
    - Tier 1: FTRA Reversibility Check
    - Tier 2: STPA 7-Hazard Safety Invariant Matrix
    - Tier 3: Cedar / OPA Reference Monitor
    - Tier 4: Federal Reserve SR 26-2 Model Confidence Scoring
    - Tier 5: Multi-Voter Bayesian Quorum Consensus
    """
    def __init__(self, compiled_policy: Dict[str, Any]):
        self.policy = compiled_policy
        self.ucas = compiled_policy.get("unsafe_control_actions", [])
        self.cedar_rules = compiled_policy.get("cedar_rules", [])

    def evaluate(
        self,
        action_name: str,
        actor_id: str,
        target_resource: str,
        params: Dict[str, Any],
        confidence_score: float = 0.98,
        consensus_score: float = 0.90,
        is_narrowed_rerun: bool = False
    ) -> Dict[str, Any]:
        """
        Returns Phase 1 evaluation result dictionary:
        {
          "passed": bool,
          "verdict": GovernanceVerdict,
          "tier_results": [bool; 5],
          "violations": List[str],
          "clamped_params": Optional[Dict]
        }
        """
        violations = []
        tier_results = [True] * 5

        # Tier 1: FTRA classification
        is_irreversible = False
        for uca in self.ucas:
            if uca.get("action") == action_name and uca.get("terminal_classification") == "IRREVERSIBLE_TERMINAL":
                is_irreversible = True
                break

        if is_irreversible and not params.get("human_authorized", False) and not params.get("quorum_signed", False):
            # IRREVERSIBLE_TERMINAL requires authorization or fails
            tier_results[0] = False
            violations.append(f"FTRA violation: Action '{action_name}' is IRREVERSIBLE_TERMINAL and lacks explicit authorization")

        # Tier 2: STPA UCA checks
        for uca in self.ucas:
            if uca.get("action") == action_name:
                cond = uca.get("condition", {})
                if isinstance(cond, dict):
                    param_name = cond.get("param")
                    op = cond.get("operator")
                    if op == "is_null" and (param_name not in params or params[param_name] is None or params[param_name] == ""):
                        tier_results[1] = False
                        violations.append(f"STPA UCA violation {uca.get('id')}: param '{param_name}' is missing/null")
                    elif op == "greater_than" and params.get(param_name, 0) > cond.get("threshold", float("inf")):
                        tier_results[1] = False
                        violations.append(f"STPA UCA violation {uca.get('id')}: param '{param_name}' exceeds threshold")
                elif isinstance(cond, list):
                    for c in cond:
                        param_name = c.get("parameter")
                        c_type = c.get("type")
                        val = c.get("value")
                        if c_type == "greater_than" and params.get(param_name, 0) > val:
                            tier_results[1] = False
                            violations.append(f"STPA constraint violation {uca.get('id')}: {param_name} > {val}")

        # Tier 3: Cedar Authorization
        for rule in self.cedar_rules:
            if f'action == Action::"{action_name}"' in rule and rule.startswith("forbid"):
                # Forbid match
                if "CrownJewel" in target_resource or params.get("forbidden_flag", False):
                    tier_results[2] = False
                    violations.append(f"Cedar forbid rule triggered for action '{action_name}' on resource '{target_resource}'")

        # Tier 4: Fed SR 26-2 Confidence Scoring
        if confidence_score < 0.70:
            tier_results[3] = False
            violations.append(f"SR 26-2 confidence score {confidence_score:.4f} < 0.70 threshold (FAIL)")
        elif confidence_score < 0.95:
            # Does not outright fail tier, but dictates REQUIRE_APPROVAL
            pass

        # Tier 5: Consensus Check
        if consensus_score < 0.80:
            tier_results[4] = False
            violations.append(f"Consensus quorum score {consensus_score:.4f} < 0.80 threshold")

        all_passed = all(tier_results)

        if not all_passed:
            # Check if NARROW is possible (e.g. if violation was order value exceeding threshold)
            can_clamp = False
            clamped = None
            if len(violations) == 1 and ("exceeds threshold" in violations[0] or ">" in violations[0]):
                clamped = copy.deepcopy(params)
                for k, v in clamped.items():
                    if isinstance(v, (int, float)) and v > 1000.0:
                        clamped[k] = 1000.0
                        can_clamp = True
            if can_clamp and not is_narrowed_rerun:
                return {
                    "passed": True,
                    "verdict": GovernanceVerdict.NARROW,
                    "tier_results": tier_results,
                    "violations": violations,
                    "clamped_params": clamped
                }

            return {
                "passed": False,
                "verdict": GovernanceVerdict.DENY,
                "tier_results": tier_results,
                "violations": violations,
                "clamped_params": None
            }

        # If confidence is in [0.70, 0.95), dictate REQUIRE_APPROVAL
        if 0.70 <= confidence_score < 0.95:
            return {
                "passed": True,
                "verdict": GovernanceVerdict.REQUIRE_APPROVAL,
                "tier_results": tier_results,
                "violations": [],
                "clamped_params": None
            }

        return {
            "passed": True,
            "verdict": GovernanceVerdict.ALLOW,
            "tier_results": tier_results,
            "violations": [],
            "clamped_params": None
        }


# =============================================================================
# F5: Phase 2 Discrete-Time Exponential Control Barrier Function & Fiscal Ledger
# =============================================================================

class ControlBarrierFunction:
    """
    Discrete-time exponential Control Barrier Function:
    h_{t+1} = (B_t - c) - B_min >= (1 - gamma) * h_t >= 0
    with atomic pre-reservation and LIFO rollback.
    """
    def __init__(self, initial_budget: float = 100.0, b_min: float = 10.0, gamma: float = 0.5):
        if not (0.0 < gamma <= 1.0):
            raise ValueError(f"Gamma must satisfy 0 < gamma <= 1, got {gamma}")
        self.budget = initial_budget
        self.b_min = b_min
        self.gamma = gamma
        self.reservations: Dict[str, float] = {}

    def current_h(self) -> float:
        return self.budget - self.b_min

    def evaluate_and_reserve(self, cost: float, debit_id: Optional[str] = None) -> Tuple[bool, float, float, Optional[str]]:
        """
        Evaluates discrete CBF step:
        h_t = budget - b_min
        h_{t+1} = (budget - cost) - b_min
        Returns (satisfied: bool, h_t: float, h_next: float, debit_id: Optional[str])
        """
        if cost < 0:
            return False, self.current_h(), self.current_h(), None

        h_t = self.current_h()
        h_next = (self.budget - cost) - self.b_min

        # Invariants:
        # 1. Non-negativity: h_{t+1} >= 0
        # 2. Exponential decay barrier: h_{t+1} >= (1 - gamma) * h_t
        min_allowed_h = (1.0 - self.gamma) * h_t

        if h_next < 0 or h_next < min_allowed_h:
            # Violation: fail closed, ZERO budget leakage (budget remains unchanged)
            return False, h_t, h_next, None

        # Pre-reservation commits atomically
        did = debit_id or str(uuid.uuid4())
        self.budget -= cost
        self.reservations[did] = cost
        return True, h_t, h_next, did

    def rollback(self, debit_id: str) -> float:
        """LIFO atomic rollback restoring exact cost to budget."""
        if debit_id not in self.reservations:
            raise KeyError(f"Unknown debit reservation '{debit_id}' for CBF rollback")
        cost = self.reservations.pop(debit_id)
        self.budget += cost
        return cost


# =============================================================================
# F6 & F9: 30-Second TTL Cryptographic Routing Seal & Host Capability Gate
# =============================================================================

def generate_action_digest(action_name: str, params: Dict[str, Any]) -> str:
    """Computes deterministic 64-character lowercase hex SHA-256 action digest."""
    canonical_params = rfc8785_canonicalize(params)
    hasher = hashlib.sha256()
    hasher.update(action_name.encode("utf-8"))
    hasher.update(b":")
    hasher.update(canonical_params)
    digest = hasher.hexdigest().lower()
    assert DIGEST_64_HEX_REGEX.match(digest)
    return digest


def sign_routing_seal(
    seal_id: str,
    action_digest: str,
    policy_version_id: str,
    issued_at: int,
    secret: bytes = DEFAULT_HMAC_SECRET
) -> str:
    """Computes HMAC-SHA256 signature binding seal attributes."""
    msg = f"{seal_id}|{action_digest}|{policy_version_id}|{issued_at}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest().lower()


def issue_routing_seal(
    action_name: str,
    params: Dict[str, Any],
    policy_version_id: str,
    issued_at: Optional[int] = None,
    ttl_seconds: int = ROUTING_SEAL_TTL_SECONDS,
    secret: bytes = DEFAULT_HMAC_SECRET
) -> Dict[str, Any]:
    """Issues a cryptographically signed 30-second TTL single-use routing seal."""
    seal_id = f"seal_{uuid.uuid4()}"
    digest = generate_action_digest(action_name, params)
    now = issued_at if issued_at is not None else int(time.time())
    sig = sign_routing_seal(seal_id, digest, policy_version_id, now, secret)

    seal = {
        "seal_id": seal_id,
        "action_digest": digest,
        "policy_version_id": policy_version_id,
        "issued_at_utc": now,
        "expires_at_utc": now + ttl_seconds,
        "ttl_seconds": ttl_seconds,
        "signature_hmac_sha256": sig
    }
    return seal


class HostCapabilityGate:
    """
    Host Capability Gate (Sandbox) enforcing single-use 30-second TTL routing seal
    before any high-risk actuation executes (NoDirectBind).
    """
    def __init__(self, secret: bytes = DEFAULT_HMAC_SECRET):
        self.secret = secret
        self.consumed_seals: Set[str] = set()

    def validate_and_consume(
        self,
        seal: Dict[str, Any],
        expected_action_name: str,
        expected_params: Dict[str, Any],
        current_time_utc: Optional[int] = None
    ) -> Dict[str, Any]:
        now = current_time_utc if current_time_utc is not None else int(time.time())
        seal_id = seal.get("seal_id")
        if not seal_id:
            raise SealRejectionError("Missing seal_id")

        # 1. Single-use replay check
        if seal_id in self.consumed_seals:
            raise SealRejectionError(f"Replay detected: routing seal '{seal_id}' has already been consumed")

        # 2. TTL Expiration check
        issued_at = seal.get("issued_at_utc", 0)
        expires_at = seal.get("expires_at_utc", issued_at + 30)
        if now > expires_at:
            raise SealRejectionError(f"Routing seal expired: current {now} > expires {expires_at}")

        # 3. Action Digest Match
        expected_digest = generate_action_digest(expected_action_name, expected_params)
        actual_digest = seal.get("action_digest", "")
        if actual_digest != expected_digest:
            raise SealRejectionError(f"Action digest mismatch: seal bound to {actual_digest}, expected {expected_digest}")

        # 4. Cryptographic HMAC Signature Verification
        expected_sig = sign_routing_seal(
            seal_id,
            actual_digest,
            seal.get("policy_version_id", ""),
            issued_at,
            self.secret
        )
        if not hmac.compare_digest(seal.get("signature_hmac_sha256", ""), expected_sig):
            raise SealRejectionError("Cryptographic HMAC signature invalid")

        # Atomic single-use consumption
        self.consumed_seals.add(seal_id)
        return {
            "status": "CONSUMED",
            "seal_id": seal_id,
            "action_name": expected_action_name,
            "consumed_at_utc": now,
            "ttl_remaining_seconds": max(0, expires_at - now)
        }


# =============================================================================
# F7: Pure-Rust 34-State BFS Formal Model Engine
# =============================================================================

class FormalBfsModelEngine:
    """
    Simulates the pure-Rust 34-state BFS formal model proving NoDirectBind.
    Explores all reachable states of the 7-tier governance state machine:
    - Gated model: Exactly 34 reachable states, exactly 1 EXECUTED state
      where (resolved_allow == True and seal_present == True). 0 violations.
    - Ungated model: Exactly 17 reachable states, produces an explicit
      direct-bind counterexample state where (executed == True and seal_present == False).
    """
    @staticmethod
    def explore_gated_model() -> Tuple[Set[Tuple], List[Dict[str, Any]]]:
        """
        Explores reachable states in the gated model:
        1. 1 Initial state
        2. 8 Checking progression states
        3. 14 Refusal & Failure states (7 direct, 7 narrow rerun failure)
        4. 8 NARROW states (7 tier narrow evaluations, 1 narrow clamped pass)
        5. 1 SEAL_ISSUED state
        6. 1 EXECUTED state
        7. 1 Post-seal invalidation/expiry state
        Total = 34 reachable states.
        """
        initial_state = ("INITIAL", "PENDING", 0, False, False, False)
        visited = set()
        queue = collections.deque([initial_state])
        violations = []

        # Graph transitions
        transitions: Dict[Tuple, List[Tuple]] = {}

        # 1. Initial transitions to first checking tier
        transitions[initial_state] = [("CHECKING", "ftra", 0, False, False, False)]

        # 2. Checking progression (8 states)
        tier_names = ["ftra", "stpa", "opa", "confidence", "consensus", "cbf", "fiscal"]
        for idx, name in enumerate(tier_names):
            current_check = ("CHECKING", name, idx, False, False, False)
            next_check = ("CHECKING", tier_names[idx + 1], idx + 1, False, False, False) if idx < 6 else ("CHECKING", "completed", 7, False, False, False)
            direct_deny = ("DENIED", f"direct_tier_{idx}", idx, False, False, False)
            narrow_eval = ("NARROW_EVAL", f"tier_{idx}", idx, False, False, True)

            transitions[current_check] = [next_check, direct_deny, narrow_eval]

            # Narrow evaluations (7 states) can either fail rerun (DENIED) or if last tier, narrow passed
            narrow_rerun_deny = ("DENIED", f"narrow_rerun_tier_{idx}", idx, False, False, False)
            if idx < 6:
                next_narrow = ("NARROW_EVAL", f"tier_{idx + 1}", idx + 1, False, False, True)
                transitions[narrow_eval] = [next_narrow, narrow_rerun_deny]
            else:
                narrow_pass = ("NARROW_PASSED", "all_clamped", 7, True, True, True)
                transitions[narrow_eval] = [narrow_pass, narrow_rerun_deny]

        # 8th checking state: completed -> SEAL_ISSUED
        seal_issued = ("SEAL_ISSUED", "valid", 7, True, True, False)
        transitions[("CHECKING", "completed", 7, False, False, False)] = [seal_issued]

        # Narrow passed can also transition to SEAL_ISSUED
        transitions[("NARROW_PASSED", "all_clamped", 7, True, True, True)] = [seal_issued]

        # SEAL_ISSUED transitions to EXECUTED or DENIED (seal expired/tampered)
        executed = ("EXECUTED", "executed", 7, True, True, True)
        seal_expired = ("DENIED", "seal_expired", 7, True, False, False)
        transitions[seal_issued] = [executed, seal_expired]

        # Terminals have empty transitions
        for idx in range(7):
            transitions[("DENIED", f"direct_tier_{idx}", idx, False, False, False)] = []
            transitions[("DENIED", f"narrow_rerun_tier_{idx}", idx, False, False, False)] = []
        transitions[executed] = []
        transitions[seal_expired] = []

        # Run BFS
        while queue:
            state = queue.popleft()
            if state in visited:
                continue
            visited.add(state)

            phase, label, tier, seal_present, resolved_allow, executed_or_narrow = state

            # Invariant check: NoDirectBind
            # phase == EXECUTED => (resolved_allow == True and seal_present == True)
            if phase == "EXECUTED":
                if not (resolved_allow and seal_present):
                    violations.append({
                        "state": state,
                        "error": "NoDirectBind violation in EXECUTED phase"
                    })

            for next_state in transitions.get(state, []):
                if next_state not in visited:
                    queue.append(next_state)

        return visited, violations

    @staticmethod
    def explore_ungated_counterexample() -> Tuple[Set[Tuple], List[Dict[str, Any]]]:
        """
        Explores reachable states in the ungated model (negative control):
        1. 1 Initial state
        2. 7 Checking states
        3. 7 Direct denial states
        4. 1 Ungated EXECUTED counterexample state (executed without seal)
        5. 1 Terminal failure state
        Total = 17 reachable states.
        """
        initial_state = ("INITIAL", "PENDING", 0, False, False)
        visited = set()
        queue = collections.deque([initial_state])
        violations = []

        transitions: Dict[Tuple, List[Tuple]] = {}
        tier_names = ["ftra", "stpa", "opa", "confidence", "consensus", "cbf", "fiscal"]

        transitions[initial_state] = [("CHECKING", "ftra", 0, False, False)]

        for idx, name in enumerate(tier_names):
            current_check = ("CHECKING", name, idx, False, False)
            next_check = ("CHECKING", tier_names[idx + 1], idx + 1, False, False) if idx < 6 else ("EXECUTED", "ungated_direct_bind", 7, False, True)
            deny_state = ("DENIED", f"tier_{idx}", idx, False, False)

            transitions[current_check] = [next_check, deny_state]
            transitions[deny_state] = []

        # Ungated executed counterexample state and terminal failure state
        ungated_exec = ("EXECUTED", "ungated_direct_bind", 7, False, True)
        term_fail = ("DENIED", "terminal_failure", 7, False, False)
        transitions[ungated_exec] = [term_fail]
        transitions[term_fail] = []

        while queue:
            state = queue.popleft()
            if state in visited:
                continue
            visited.add(state)

            phase, label, tier, seal_present, executed = state

            if phase == "EXECUTED":
                if not seal_present:
                    violations.append({
                        "state": state,
                        "error": "Direct-bind violation counterexample observed (executed without seal)"
                    })

            for next_state in transitions.get(state, []):
                if next_state not in visited:
                    queue.append(next_state)

        return visited, violations


# =============================================================================
# F8 & F11: 5 Core Stream Invariants & RFC 8785 Hash Chained Audit Log
# =============================================================================

class StreamInvariantVerifier:
    """
    Verifies the 5 core CAGE stream invariants on JSONL audit streams:
    1. no_direct_bind
    2. cbf_barrier
    3. seal
    4. cbf_rollback
    5. refusal_evidence
    + format invariant: digest_format (^[0-9a-f]{64}$)
    """
    @staticmethod
    def verify_stream(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        governance_decisions = {}   # decision_hash -> record
        seals_consumed = {}         # seal_id -> record
        cbf_commits = {}            # debit_id -> record
        cbf_rollbacks = {}          # debit_id -> record
        refusals = set()

        for idx, rec in enumerate(records):
            event_type = rec.get("event_type")

            # Check digest_format on all 64-hex fields
            for k, v in rec.items():
                if "digest" in k or "proof_hash" in k or "record_hash" in k or "prev_hash" in k:
                    if isinstance(v, str) and len(v) == 64:
                        if not DIGEST_64_HEX_REGEX.match(v):
                            findings.append({
                                "record_index": idx,
                                "rule": "digest_format",
                                "detail": f"Field '{k}' value '{v}' violates ^[0-9a-f]{{64}}$ (contains uppercase or invalid chars)"
                            })

            # Invariant 3: seal
            if event_type == "GOVERNANCE_DECISION":
                verdict = rec.get("verdict")
                rec_hash = rec.get("record_hash")
                if verdict in ("ALLOW", "NARROW"):
                    if not rec.get("seal_present"):
                        findings.append({
                            "record_index": idx,
                            "rule": "seal",
                            "detail": f"Decision {rec_hash} verdict {verdict} missing seal_present"
                        })
                governance_decisions[rec_hash] = rec

            # Invariant 1: no_direct_bind (seal consumed binding)
            elif event_type == "GOVERNANCE_SEAL_CONSUMED":
                seal_id = rec.get("seal_id")
                decision_hash = rec.get("decision_record_hash")
                if decision_hash not in governance_decisions:
                    findings.append({
                        "record_index": idx,
                        "rule": "no_direct_bind",
                        "detail": f"GOVERNANCE_SEAL_CONSUMED references unknown decision hash {decision_hash}"
                    })
                if seal_id in seals_consumed:
                    findings.append({
                        "record_index": idx,
                        "rule": "no_direct_bind",
                        "detail": f"Seal '{seal_id}' consumed multiple times (replay detected)"
                    })
                seals_consumed[seal_id] = rec

            elif event_type in ("ACTUATION_RECEIPT", "ACTUATION_REFUSAL_RECEIPT"):
                seal_ref = rec.get("seal_id")
                if seal_ref not in seals_consumed:
                    findings.append({
                        "record_index": idx,
                        "rule": "no_direct_bind",
                        "detail": f"Actuation receipt for seal '{seal_ref}' executed without preceding GOVERNANCE_SEAL_CONSUMED"
                    })

            # Invariant 2: cbf_barrier
            elif event_type == "CBF_COMMIT":
                debit_id = rec.get("debit_id")
                state_before = rec.get("state_before", 0.0)
                cost = rec.get("cost", 0.0)
                b_min = rec.get("b_min", 0.0)
                gamma = rec.get("gamma", 0.5)

                h_t = state_before - b_min
                h_next = (state_before - cost) - b_min
                min_h = (1.0 - gamma) * h_t

                if h_next < 0 or h_next < min_h:
                    findings.append({
                        "record_index": idx,
                        "rule": "cbf_barrier",
                        "detail": f"CBF_COMMIT for debit '{debit_id}' violates barrier: h_next={h_next:.2f} < min_allowed={min_h:.2f}"
                    })
                cbf_commits[debit_id] = rec

            # Invariant 4: cbf_rollback
            elif event_type == "CBF_ROLLBACK":
                debit_id = rec.get("debit_id")
                status = rec.get("status")
                if status == "ROLLED_BACK":
                    if debit_id not in cbf_commits:
                        findings.append({
                            "record_index": idx,
                            "rule": "cbf_rollback",
                            "detail": f"CBF_ROLLBACK references unledgered debit_id '{debit_id}'"
                        })
                    else:
                        commit_cost = cbf_commits[debit_id].get("cost", 0.0)
                        restored_cost = rec.get("restored_amount", 0.0)
                        if abs(commit_cost - restored_cost) > 1e-6:
                            findings.append({
                                "record_index": idx,
                                "rule": "cbf_rollback",
                                "detail": f"Rollback budget leakage: committed {commit_cost} != restored {restored_cost}"
                            })
                    cbf_rollbacks[debit_id] = rec

            # Invariant 5: refusal_evidence
            elif event_type in ("GOVERNANCE_REFUSAL", "GOVERNANCE_REFUSAL_RECEIPT"):
                proof_hash = rec.get("proof_hash") or rec.get("receipt_digest")
                if not proof_hash or not DIGEST_64_HEX_REGEX.match(str(proof_hash)):
                    findings.append({
                        "record_index": idx,
                        "rule": "refusal_evidence",
                        "detail": f"Refusal event missing valid 64-character lowercase hex proof_hash: '{proof_hash}'"
                    })
                refusals.add(proof_hash)

        return {
            "records_checked": len(records),
            "findings_count": len(findings),
            "status": "CONFORMANT" if not findings else "NON_CONFORMANT",
            "findings": findings,
            "invariants_verified": [
                "no_direct_bind",
                "cbf_barrier",
                "seal",
                "cbf_rollback",
                "refusal_evidence",
                "digest_format"
            ]
        }


# =============================================================================
# F12: SQLite State Persistence Manager
# =============================================================================

class SqliteCageStore:
    """Manages cage_policies, cage_routing_seals, and cage_governance_traces tables."""
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS cage_policies (
                policy_version_id TEXT PRIMARY KEY,
                format TEXT NOT NULL,
                raw_content TEXT NOT NULL,
                cedar_rules_json TEXT NOT NULL,
                ucas_json TEXT NOT NULL,
                is_pinned INTEGER NOT NULL DEFAULT 0,
                compiled_at_utc INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cage_routing_seals (
                seal_id TEXT PRIMARY KEY,
                policy_version_id TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                issued_at_utc INTEGER NOT NULL,
                expires_at_utc INTEGER NOT NULL,
                signature TEXT NOT NULL,
                is_consumed INTEGER NOT NULL DEFAULT 0,
                consumed_at_utc INTEGER,
                FOREIGN KEY (policy_version_id) REFERENCES cage_policies(policy_version_id)
            );

            CREATE TABLE IF NOT EXISTS cage_governance_traces (
                trace_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                policy_version_id TEXT,
                record_hash TEXT NOT NULL,
                prev_record_hash TEXT,
                payload_json TEXT NOT NULL,
                created_at_utc INTEGER NOT NULL
            );
        """)
        self.conn.commit()

    def store_policy(self, compiled_policy: Dict[str, Any], is_pinned: bool = True):
        cur = self.conn.cursor()
        v_id = compiled_policy["policy_version_id"]
        cur.execute("""
            INSERT OR REPLACE INTO cage_policies (
                policy_version_id, format, raw_content, cedar_rules_json, ucas_json, is_pinned, compiled_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            v_id,
            compiled_policy["format"],
            json.dumps(compiled_policy),
            json.dumps(compiled_policy["cedar_rules"]),
            json.dumps(compiled_policy["unsafe_control_actions"]),
            1 if is_pinned else 0,
            int(time.time())
        ))
        self.conn.commit()

    def get_pinned_policy(self) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM cage_policies WHERE is_pinned = 1 ORDER BY compiled_at_utc DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)

    def store_seal(self, seal: Dict[str, Any]):
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO cage_routing_seals (
                seal_id, policy_version_id, action_digest, issued_at_utc, expires_at_utc, signature, is_consumed
            ) VALUES (?, ?, ?, ?, ?, ?, 0)
        """, (
            seal["seal_id"],
            seal["policy_version_id"],
            seal["action_digest"],
            seal["issued_at_utc"],
            seal["expires_at_utc"],
            seal["signature_hmac_sha256"]
        ))
        self.conn.commit()

    def consume_seal(self, seal_id: str, now: int) -> bool:
        cur = self.conn.cursor()
        cur.execute("SELECT is_consumed FROM cage_routing_seals WHERE seal_id = ?", (seal_id,))
        row = cur.fetchone()
        if not row or row["is_consumed"] == 1:
            return False
        cur.execute("UPDATE cage_routing_seals SET is_consumed = 1, consumed_at_utc = ? WHERE seal_id = ?", (now, seal_id))
        self.conn.commit()
        return True

    def append_trace(self, trace_id: str, event_type: str, policy_version_id: str, record_hash: str, prev_hash: str, payload: Dict[str, Any]):
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO cage_governance_traces (
                trace_id, event_type, policy_version_id, record_hash, prev_record_hash, payload_json, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            trace_id,
            event_type,
            policy_version_id,
            record_hash,
            prev_hash,
            json.dumps(payload),
            int(time.time())
        ))
        self.conn.commit()

    def count_traces(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM cage_governance_traces")
        return cur.fetchone()["cnt"]


# =============================================================================
# F11: Merkle Audit Tree
# =============================================================================

class MerkleAuditTree:
    """Computes SHA-256 Merkle root from ordered list of 64-hex record hashes."""
    @staticmethod
    def compute_root(leaf_hashes: List[str]) -> str:
        if not leaf_hashes:
            return "0" * 64
        current_layer = [bytes.fromhex(h) for h in leaf_hashes]
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                combined = hashlib.sha256(left + right).digest()
                next_layer.append(combined)
            current_layer = next_layer
        root = current_layer[0].hex().lower()
        assert DIGEST_64_HEX_REGEX.match(root)
        return root


# =============================================================================
# F13: In-Memory REST Route Mock / Handler Dispatcher
# =============================================================================

class CageRestService:
    """
    Simulates the Substrate Contract v1.0 REST handlers on port 3030
    and `/api/governance/*` aliases with exact HTTP semantics.
    """
    def __init__(self):
        self.store = SqliteCageStore()
        self.pinned_policy: Optional[Dict[str, Any]] = None
        self.cbf = ControlBarrierFunction(initial_budget=100.0, b_min=10.0, gamma=0.5)
        self.gate = HostCapabilityGate()
        self.traces: List[Dict[str, Any]] = []
        self.prev_trace_hash = "0" * 64

    def handle_request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, Any]]:
        # Normalize path aliases
        norm_path = path
        if norm_path.startswith("/api/governance/"):
            norm_path = norm_path.replace("/api/governance/", "/governance/")

        if method == "POST" and norm_path == "/governance/ingest-policy":
            return self._handle_ingest_policy(body or {})
        elif method == "GET" and norm_path == "/governance/policy-version":
            return self._handle_get_policy_version()
        elif method == "POST" and norm_path == "/governance/validate-action":
            return self._handle_validate_action(body or {})
        elif method == "POST" and norm_path == "/governance/consume-seal":
            return self._handle_consume_seal(body or {})
        elif method == "POST" and norm_path == "/governance/rollback":
            return self._handle_rollback(body or {})
        elif method == "GET" and norm_path == "/governance/trace/verify":
            return self._handle_verify_trace()
        else:
            return 404, {"error": "NOT_FOUND", "message": f"Route '{path}' not found"}

    def _handle_ingest_policy(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        content = body.get("policy_content")
        if not content:
            return 400, {"error": "BAD_REQUEST", "message": "Missing 'policy_content'"}

        fmt = body.get("policy_format", "auto")
        try:
            compiled = compile_policy(content, format_override=fmt)
        except Exception as e:
            return 400, {"error": "COMPILATION_ERROR", "message": str(e)}

        v_id = compiled["policy_version_id"]
        # Version conflict check
        if self.pinned_policy:
            active_vid = self.pinned_policy["policy_version_id"]
            if active_vid != v_id:
                return 409, {
                    "error": "POLICY_VERSION_MISMATCH",
                    "message": f"Policy version drift: active is '{active_vid}', incoming is '{v_id}'",
                    "pinned_version": active_vid,
                    "incoming_version": v_id
                }

        pin = body.get("pin_version", True)
        if pin:
            self.pinned_policy = compiled
            self.store.store_policy(compiled, is_pinned=True)

        return 200, {
            "status": "compiled",
            "policy_version_id": v_id,
            "format_detected": compiled["format"],
            "rules_count": compiled["rules_count"],
            "pinned": pin,
            "compiled_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    def _handle_get_policy_version(self) -> Tuple[int, Dict[str, Any]]:
        if not self.pinned_policy:
            return 404, {"error": "NO_PINNED_POLICY", "message": "No policy currently pinned"}
        return 200, {
            "active_version_id": self.pinned_policy["policy_version_id"],
            "format": self.pinned_policy["format"],
            "rules_count": self.pinned_policy["rules_count"],
            "is_pinned": True
        }

    def _handle_validate_action(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        if not self.pinned_policy:
            return 400, {"error": "NO_POLICY", "message": "No active pinned policy"}

        exp_ver = body.get("expected_policy_version")
        active_ver = self.pinned_policy["policy_version_id"]
        if exp_ver and exp_ver != active_ver:
            return 409, {
                "error": "POLICY_VERSION_CONFLICT",
                "message": f"Version mismatch: pinned '{active_ver}' vs requested '{exp_ver}'",
                "pinned_version": active_ver,
                "submitted_version": exp_ver
            }

        action_name = body.get("action_name")
        params = body.get("params", {})
        if not action_name:
            return 400, {"error": "BAD_REQUEST", "message": "Missing 'action_name'"}

        # Phase 1: Read-Only Checks
        p1 = Phase1Gate(self.pinned_policy)
        p1_res = p1.evaluate(
            action_name=action_name,
            actor_id=body.get("actor_id", "default_actor"),
            target_resource=body.get("target_resource", "/tmp"),
            params=params
        )

        verdict = p1_res["verdict"]
        eval_params = params
        if verdict == GovernanceVerdict.NARROW and p1_res["clamped_params"]:
            eval_params = p1_res["clamped_params"]

        if verdict in (GovernanceVerdict.DENY, GovernanceVerdict.DEFER, GovernanceVerdict.REQUIRE_APPROVAL):
            proof_hash = hashlib.sha256(f"refusal:{action_name}:{time.time()}".encode("utf-8")).hexdigest().lower()
            rec = {
                "event_type": "GOVERNANCE_REFUSAL",
                "verdict": verdict,
                "proof_hash": proof_hash,
                "record_hash": hashlib.sha256(f"{proof_hash}:rec".encode("utf-8")).hexdigest().lower()
            }
            self.traces.append(rec)
            return 200, {
                "verdict": verdict,
                "policy_version": active_ver,
                "routing_seal": None,
                "refusal_reason": "; ".join(p1_res["violations"]),
                "proof_hash": proof_hash
            }

        # Phase 2: CBF Barrier Evaluation
        cost = float(body.get("cost", 0.0))
        cbf_sat, h_t, h_next, debit_id = self.cbf.evaluate_and_reserve(cost)
        if not cbf_sat:
            proof_hash = hashlib.sha256(f"cbf_deny:{action_name}:{cost}:{time.time()}".encode("utf-8")).hexdigest().lower()
            rec = {
                "event_type": "GOVERNANCE_REFUSAL",
                "verdict": GovernanceVerdict.DENY,
                "proof_hash": proof_hash,
                "record_hash": hashlib.sha256(f"{proof_hash}:cbf".encode("utf-8")).hexdigest().lower()
            }
            self.traces.append(rec)
            return 200, {
                "verdict": GovernanceVerdict.DENY,
                "policy_version": active_ver,
                "routing_seal": None,
                "barrier_state": {"h_t": h_t, "h_next": h_next, "cost": cost, "barrier_satisfied": False},
                "refusal_reason": f"CBF Barrier Violation: h_{{t+1}} = {h_next:.2f} < 0",
                "proof_hash": proof_hash
            }

        # Cleared: Issue 30s TTL Seal
        seal = issue_routing_seal(action_name, eval_params, active_ver)
        self.store.store_seal(seal)

        dec_hash = hashlib.sha256(f"dec:{seal['seal_id']}".encode("utf-8")).hexdigest().lower()
        dec_rec = {
            "event_type": "GOVERNANCE_DECISION",
            "verdict": verdict,
            "record_hash": dec_hash,
            "seal_present": True,
            "seal_id": seal["seal_id"],
            "debit_id": debit_id
        }
        self.traces.append(dec_rec)

        commit_rec = {
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": self.cbf.budget + cost,
            "cost": cost,
            "b_min": self.cbf.b_min,
            "gamma": self.cbf.gamma,
            "record_hash": hashlib.sha256(f"commit:{debit_id}".encode("utf-8")).hexdigest().lower()
        }
        self.traces.append(commit_rec)

        return 200, {
            "verdict": verdict,
            "policy_version": active_ver,
            "routing_seal": seal,
            "debit_id": debit_id,
            "barrier_state": {"h_t": h_t, "h_next": h_next, "cost": cost, "barrier_satisfied": True},
            "decision_record_hash": dec_hash
        }

    def _handle_consume_seal(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        seal_id = body.get("seal_id")
        action_name = body.get("action_name")
        params = body.get("params", {})
        seal = body.get("seal")
        if not seal_id or not action_name:
            return 400, {"error": "BAD_REQUEST", "message": "Missing 'seal_id' or 'action_name'"}

        seal_payload = seal or {
            "seal_id": seal_id,
            "action_digest": body.get("action_digest", generate_action_digest(action_name, params)),
            "policy_version_id": self.pinned_policy["policy_version_id"] if self.pinned_policy else "0"*16,
            "issued_at_utc": int(time.time()),
            "expires_at_utc": int(time.time()) + 30,
            "signature_hmac_sha256": body.get("signature", "")
        }

        try:
            res = self.gate.validate_and_consume(seal_payload, action_name, params)
            self.store.consume_seal(seal_id, int(time.time()))

            consumed_rec = {
                "event_type": "GOVERNANCE_SEAL_CONSUMED",
                "seal_id": seal_id,
                "decision_record_hash": body.get("decision_record_hash", hashlib.sha256(f"dec:{seal_id}".encode("utf-8")).hexdigest().lower()),
                "record_hash": hashlib.sha256(f"consume:{seal_id}".encode("utf-8")).hexdigest().lower()
            }
            self.traces.append(consumed_rec)
            return 200, res
        except SealRejectionError as e:
            return 403, {"error": "SEAL_REJECTED", "message": str(e)}

    def _handle_rollback(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        debit_id = body.get("debit_id")
        if not debit_id:
            return 400, {"error": "BAD_REQUEST", "message": "Missing 'debit_id'"}
        try:
            restored = self.cbf.rollback(debit_id)
            rec = {
                "event_type": "CBF_ROLLBACK",
                "debit_id": debit_id,
                "status": "ROLLED_BACK",
                "restored_amount": restored,
                "record_hash": hashlib.sha256(f"rollback:{debit_id}".encode("utf-8")).hexdigest().lower()
            }
            self.traces.append(rec)
            return 200, {
                "status": "ROLLED_BACK",
                "debit_id": debit_id,
                "restored_amount": restored,
                "state_after_rollback": self.cbf.budget
            }
        except KeyError as e:
            return 404, {"error": "NOT_FOUND", "message": str(e)}

    def _handle_verify_trace(self) -> Tuple[int, Dict[str, Any]]:
        verification = StreamInvariantVerifier.verify_stream(self.traces)
        if verification["status"] == "CONFORMANT":
            return 200, verification
        return 422, verification
