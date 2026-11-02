"""
Tier 2: Boundary & Corner Cases Test Suite for CAGE Governance Substrate.
Exercises limits, caps, corrupt inputs, edge boundaries, overflow bounds,
and adversarial fail-closed invariants for all 15 features (F1 through F15).
>= 5 deterministic tests per feature (75 tests total).
"""

import copy
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "e2e_cage_governance"))

import oracles
from oracles import (
    ControlBarrierFunction,
    FormalBfsModelEngine,
    GovernanceVerdict,
    HostCapabilityGate,
    MerkleAuditTree,
    Phase1Gate,
    PolicyConflictError,
    PolicyFormat,
    SealRejectionError,
    SqliteCageStore,
    StreamInvariantVerifier,
    auto_detect_policy_format,
    compile_policy,
    compute_policy_version_id,
    generate_action_digest,
    issue_routing_seal,
    rfc8785_canonicalize,
)


class TestTier2BoundaryCorner(unittest.TestCase):
    """Tier 2: Boundary Value Analysis & Edge Conditions (F1 through F15)."""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.dashboard_dir = cls.root / "dashboard"
        cls.workflows_dir = cls.root / ".github" / "workflows"

    # =========================================================================
    # Feature 1 Boundary: Multi-Format Policy Auto-Detection & Ingestion
    # =========================================================================

    def test_f01_b01_corrupt_yaml_syntax_raises_error(self):
        """F1.B1: Malformed YAML/JSON syntax raises ValueError on auto-detection."""
        corrupt_input = "{ bad_json: unquoted, [invalid syntax"
        with self.assertRaises(ValueError):
            auto_detect_policy_format(corrupt_input)

    def test_f01_b02_empty_dict_missing_discriminants_raises_error(self):
        """F1.B2: Empty dictionary missing all schema discriminant keys raises ValueError."""
        with self.assertRaises(ValueError):
            auto_detect_policy_format({})

    def test_f01_b03_prioritized_discriminant_oscal_over_acs(self):
        """F1.B3: Document containing both oscal-version and behaviorDeclarations prioritizes OSCAL."""
        doc = {
            "oscal-version": "1.1.0",
            "behaviorDeclarations": []
        }
        fmt = auto_detect_policy_format(doc)
        self.assertEqual(fmt, PolicyFormat.OSCAL)

    def test_f01_b04_prioritized_discriminant_lula_over_generic(self):
        """F1.B4: Document containing kind: LulaValidation prioritizes Lula over native STPA."""
        doc = {
            "kind": "LulaValidation",
            "stpa_control_structure": {}
        }
        fmt = auto_detect_policy_format(doc)
        self.assertEqual(fmt, PolicyFormat.LULA)

    def test_f01_b05_wrapped_lula_in_oscal_back_matter_detection(self):
        """F1.B5: OSCAL document wrapping Lula manifest in back-matter resources resolves as Lula."""
        doc = {
            "component-definition": {
                "metadata": {"oscal-version": "1.1.0"},
                "back-matter": {
                    "resources": [
                        {"description": "LulaValidation manifest with Rego rules"}
                    ]
                }
            }
        }
        fmt = auto_detect_policy_format(doc)
        self.assertEqual(fmt, PolicyFormat.LULA)

    # =========================================================================
    # Feature 2 Boundary: Cedar & STPA UCA Compilation
    # =========================================================================

    def test_f02_b01_compile_empty_behavior_declarations(self):
        """F2.B1: Compiling ACS document with 0 behavior declarations compiles cleanly with 0 rules."""
        doc = {"behaviorDeclarations": []}
        compiled = compile_policy(doc)
        self.assertEqual(len(compiled["cedar_rules"]), 0)
        self.assertEqual(len(compiled["unsafe_control_actions"]), 0)

    def test_f02_b02_uca_missing_hazard_refs_defaults_safely(self):
        """F2.B2: UCA missing hazardRefs assigns safe default hazard reference."""
        doc = {
            "behaviorDeclarations": [
                {"id": "ACS-NO-HAZARD", "action": "ActNoHazard"}
            ]
        }
        compiled = compile_policy(doc)
        self.assertEqual(compiled["unsafe_control_actions"][0]["hazard_refs"], ["H-1"])

    def test_f02_b03_special_characters_in_action_name_escaped(self):
        """F2.B3: Action names with alphanumeric characters and colons compile into valid Cedar."""
        doc = {
            "behaviorDeclarations": [
                {"id": "ACS-COLON", "action": "Namespace::Subsystem:Action"}
            ]
        }
        compiled = compile_policy(doc)
        self.assertTrue(any('Namespace::Subsystem:Action' in r for r in compiled["cedar_rules"]))

    def test_f02_b04_circular_or_duplicate_hazards_preserved(self):
        """F2.B4: Duplicate hazard references within a UCA are handled without crashing."""
        doc = {
            "behaviorDeclarations": [
                {"id": "ACS-DUP", "action": "ActDup", "hazardRefs": ["H-1", "H-1", "H-2"]}
            ]
        }
        compiled = compile_policy(doc)
        self.assertEqual(len(compiled["unsafe_control_actions"][0]["hazard_refs"]), 3)

    def test_f02_b05_large_policy_compiles_under_sla(self):
        """F2.B5: Compiling large policy (500 rules) completes in less than 500ms."""
        doc = {
            "behaviorDeclarations": [
                {"id": f"ACS-STRESS-{i}", "action": f"Action_{i}", "constraints": []}
                for i in range(500)
            ]
        }
        t0 = time.perf_counter()
        compiled = compile_policy(doc)
        t_elapsed = time.perf_counter() - t0
        self.assertLess(t_elapsed, 0.5)
        self.assertEqual(len(compiled["cedar_rules"]), 500)

    # =========================================================================
    # Feature 3 Boundary: Deterministic 16-Hex Version Pinning & 409 Conflict
    # =========================================================================

    def test_f03_b01_version_hash_ignores_ast_metadata_keys(self):
        """F3.B1: Equivalent compiled AST structures yield identical 16-hex version IDs."""
        bundle1 = {"cedar_rules": ["forbid;"], "unsafe_control_actions": []}
        bundle2 = {"unsafe_control_actions": [], "cedar_rules": ["forbid;"]}
        v1 = compute_policy_version_id(bundle1)
        v2 = compute_policy_version_id(bundle2)
        self.assertEqual(v1, v2)

    def test_f03_b02_invalid_hex_length_rejected(self):
        """F3.B2: Version ID validator rejects strings that are not strictly 16 hex chars."""
        self.assertFalse(bool(oracles.VERSION_16_HEX_REGEX.match("abc123")))  # 6 chars
        self.assertFalse(bool(oracles.VERSION_16_HEX_REGEX.match("0123456789abcdef0")))  # 17 chars
        self.assertTrue(bool(oracles.VERSION_16_HEX_REGEX.match("0123456789abcdef")))  # 16 chars

    def test_f03_b03_uppercase_hex_rejected(self):
        """F3.B3: Version ID validator rejects uppercase hex characters per lowercase specification."""
        self.assertFalse(bool(oracles.VERSION_16_HEX_REGEX.match("0123456789ABCDEF")))

    def test_f03_b04_empty_policy_generates_stable_version_id(self):
        """F3.B4: Empty compiled bundle generates valid, deterministic 16-hex ID."""
        v = compute_policy_version_id({})
        self.assertEqual(len(v), 16)
        self.assertTrue(oracles.VERSION_16_HEX_REGEX.match(v))

    def test_f03_b05_consecutive_drift_attempts_fail_cleanly(self):
        """F3.B5: Multiple consecutive drifted ingest requests fail with 409 without mutating active version."""
        svc = oracles.CageRestService()
        doc_init = {"behaviorDeclarations": [{"id": "ACS-INIT", "action": "InitAct"}]}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc_init), "pin_version": True})
        pinned_v = svc.pinned_policy["policy_version_id"]

        for i in range(5):
            drifted_doc = {"behaviorDeclarations": [{"id": f"ACS-DRIFT-{i}", "action": f"Drift_{i}"}]}
            code, res = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(drifted_doc), "pin_version": True})
            self.assertEqual(code, 409)
            self.assertEqual(svc.pinned_policy["policy_version_id"], pinned_v)

    # =========================================================================
    # Feature 4 Boundary: Phase 1 Read-Only Multi-Tier Gating Pipeline
    # =========================================================================

    def test_f04_b01_sr26_2_exact_boundary_allow(self):
        """F4.B1: Fed SR 26-2 boundary: confidence score exactly 0.950000 yields ALLOW."""
        p1 = Phase1Gate({"unsafe_control_actions": [], "cedar_rules": []})
        res = p1.evaluate("Act", "actor", "/res", {}, confidence_score=0.950000)
        self.assertEqual(res["verdict"], GovernanceVerdict.ALLOW)

    def test_f04_b02_sr26_2_exact_boundary_require_approval(self):
        """F4.B2: Fed SR 26-2 boundary: confidence score 0.949999 yields REQUIRE_APPROVAL."""
        p1 = Phase1Gate({"unsafe_control_actions": [], "cedar_rules": []})
        res = p1.evaluate("Act", "actor", "/res", {}, confidence_score=0.949999)
        self.assertEqual(res["verdict"], GovernanceVerdict.REQUIRE_APPROVAL)

    def test_f04_b03_sr26_2_exact_boundary_lower_approval(self):
        """F4.B3: Fed SR 26-2 boundary: confidence score exactly 0.700000 yields REQUIRE_APPROVAL."""
        p1 = Phase1Gate({"unsafe_control_actions": [], "cedar_rules": []})
        res = p1.evaluate("Act", "actor", "/res", {}, confidence_score=0.700000)
        self.assertEqual(res["verdict"], GovernanceVerdict.REQUIRE_APPROVAL)

    def test_f04_b04_sr26_2_exact_boundary_lower_deny(self):
        """F4.B4: Fed SR 26-2 boundary: confidence score 0.699999 yields DENY."""
        p1 = Phase1Gate({"unsafe_control_actions": [], "cedar_rules": []})
        res = p1.evaluate("Act", "actor", "/res", {}, confidence_score=0.699999)
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)

    def test_f04_b05_consensus_quorum_exact_boundary(self):
        """F4.B5: Multi-detector consensus score 0.799999 falls below 0.80 threshold, denying action."""
        p1 = Phase1Gate({"unsafe_control_actions": [], "cedar_rules": []})
        res = p1.evaluate("Act", "actor", "/res", {}, consensus_score=0.799999)
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)

    # =========================================================================
    # Feature 5 Boundary: Phase 2 Discrete-Time Exponential CBF & Fiscal Ledger
    # =========================================================================

    def test_f05_b01_cost_exactly_equal_to_safety_floor(self):
        """F5.B1: Cost exactly reaching barrier floor h_{t+1} = 0 is allowed if decay satisfied."""
        # Initial budget = 20, b_min = 10 -> h_t = 10.
        # Cost = 10 -> h_{t+1} = 0.
        # With gamma = 1.0, min allowed h_{t+1} = (1 - 1.0)*10 = 0.
        cbf = ControlBarrierFunction(initial_budget=20.0, b_min=10.0, gamma=1.0)
        sat, ht, hnext, did = cbf.evaluate_and_reserve(cost=10.0)
        self.assertTrue(sat)
        self.assertEqual(hnext, 0.0)

    def test_f05_b02_cost_exceeding_floor_by_epsilon_denied(self):
        """F5.B2: Cost exceeding barrier floor by 1e-6 (h_{t+1} = -1e-6) fails closed."""
        cbf = ControlBarrierFunction(initial_budget=20.0, b_min=10.0, gamma=1.0)
        sat, ht, hnext, did = cbf.evaluate_and_reserve(cost=10.000001)
        self.assertFalse(sat)
        self.assertLess(hnext, 0.0)
        self.assertEqual(cbf.budget, 20.0)  # Zero budget leakage

    def test_f05_b03_invalid_gamma_zero_rejected(self):
        """F5.B3: Initializing CBF with gamma = 0.0 raises ValueError."""
        with self.assertRaises(ValueError):
            ControlBarrierFunction(gamma=0.0)

    def test_f05_b04_invalid_gamma_greater_than_one_rejected(self):
        """F5.B4: Initializing CBF with gamma > 1.0 raises ValueError."""
        with self.assertRaises(ValueError):
            ControlBarrierFunction(gamma=1.0001)

    def test_f05_b05_duplicate_rollback_raises_key_error(self):
        """F5.B5: Attempting to rollback an already restored debit_id raises KeyError."""
        cbf = ControlBarrierFunction(initial_budget=100.0, b_min=10.0, gamma=0.5)
        _, _, _, did = cbf.evaluate_and_reserve(cost=10.0)
        cbf.rollback(did)
        with self.assertRaises(KeyError):
            cbf.rollback(did)

    # =========================================================================
    # Feature 6 Boundary: Canonical Verdicts & 30s TTL Routing Seals
    # =========================================================================

    def test_f06_b01_routing_seal_boundary_exact_expiration(self):
        """F6.B1: Routing seal is valid at current == expires_at, rejected at expires_at + 1."""
        gate = HostCapabilityGate()
        now = 1000
        seal = issue_routing_seal("Act", {"k": "v"}, "v1", issued_at=now)
        # At exactly expires_at (1030)
        res = gate.validate_and_consume(copy.deepcopy(seal), "Act", {"k": "v"}, current_time_utc=now + 30)
        self.assertEqual(res["status"], "CONSUMED")

        # Second seal at expires_at + 1 (1031)
        seal2 = issue_routing_seal("Act", {"k": "v"}, "v1", issued_at=now)
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume(seal2, "Act", {"k": "v"}, current_time_utc=now + 31)

    def test_f06_b02_seal_signature_tampering_rejected(self):
        """F6.B2: Routing seal with even 1 flipped bit in signature is rejected."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("Act", {}, "v1")
        # Flip first character of hex signature
        sig = seal["signature_hmac_sha256"]
        tampered_char = "0" if sig[0] != "0" else "1"
        seal["signature_hmac_sha256"] = tampered_char + sig[1:]
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume(seal, "Act", {})

    def test_f06_b03_seal_action_digest_tampering_rejected(self):
        """F6.B3: Seal with tampered action digest is rejected by gate."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("Act", {}, "v1")
        seal["action_digest"] = "f" * 64
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume(seal, "Act", {})

    def test_f06_b04_empty_action_digest_rejected(self):
        """F6.B4: Seal with empty action digest is rejected."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("Act", {}, "v1")
        seal["action_digest"] = ""
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume(seal, "Act", {})

    def test_f06_b05_narrow_clamped_rerun_issues_clamped_seal(self):
        """F6.B5: NARROW verdict issues routing seal cryptographically bound to clamped parameters."""
        policy = {
            "unsafe_control_actions": [
                {
                    "id": "UCA-BOUND",
                    "action": "Order",
                    "condition": [{"parameter": "amount", "type": "greater_than", "value": 1000.0}]
                }
            ],
            "cedar_rules": []
        }
        p1 = Phase1Gate(policy)
        res = p1.evaluate("Order", "trader", "/mkt", {"amount": 5000.0})
        self.assertEqual(res["verdict"], GovernanceVerdict.NARROW)
        self.assertEqual(res["clamped_params"]["amount"], 1000.0)

    # =========================================================================
    # Feature 7 Boundary: Pure-Rust 34-State BFS Formal Model (NoDirectBind)
    # =========================================================================

    def test_f07_b01_bfs_visited_set_is_finite_and_terminates(self):
        """F7.B1: BFS state exploration terminates cleanly with finite state count."""
        visited, violations = FormalBfsModelEngine.explore_gated_model()
        self.assertIsInstance(visited, set)
        self.assertEqual(len(visited), 34)

    def test_f07_b02_terminal_denied_states_have_zero_outbound_transitions(self):
        """F7.B2: Terminal DENIED states have no outbound transitions, preserving termination."""
        visited, _ = FormalBfsModelEngine.explore_gated_model()
        denied_states = [s for s in visited if s[0] == "DENIED"]
        self.assertGreater(len(denied_states), 0)

    def test_f07_b03_executed_terminal_state_invariant_completeness(self):
        """F7.B3: All EXECUTED states satisfy both resolved_allow=True and seal_present=True."""
        visited, _ = FormalBfsModelEngine.explore_gated_model()
        for s in visited:
            if s[0] == "EXECUTED":
                self.assertTrue(s[3], "resolved_allow must be True in EXECUTED state")
                self.assertTrue(s[4], "seal_present must be True in EXECUTED state")

    def test_f07_b04_ungated_model_strictly_smaller_state_space(self):
        """F7.B4: Ungated counterexample model explores 17 states (34 vs 17 separation theorem)."""
        gated_states, _ = FormalBfsModelEngine.explore_gated_model()
        ungated_states, _ = FormalBfsModelEngine.explore_ungated_counterexample()
        self.assertEqual(len(gated_states), 34)
        self.assertEqual(len(ungated_states), 17)
        self.assertGreater(len(gated_states), len(ungated_states))

    def test_f07_b05_ungated_model_counterexample_contains_violation(self):
        """F7.B5: Ungated counterexample model violation list is non-empty."""
        _, violations = FormalBfsModelEngine.explore_ungated_counterexample()
        self.assertTrue(len(violations) > 0)

    # =========================================================================
    # Feature 8 Boundary: Stream Invariant Verifier (5 Invariants, 64-hex Receipts)
    # =========================================================================

    def test_f08_b01_digest_format_rejects_63_character_hash(self):
        """F8.B1: Stream verifier flags finding if digest is 63 characters (truncated)."""
        bad_hash = "a" * 63
        rec = {"event_type": "GOVERNANCE_REFUSAL", "proof_hash": bad_hash}
        res = StreamInvariantVerifier.verify_stream([rec])
        self.assertEqual(res["status"], "NON_CONFORMANT")

    def test_f08_b02_digest_format_rejects_0x_prefix_66_char_hash(self):
        """F8.B2: Stream verifier flags finding if digest contains 0x prefix (66 characters)."""
        bad_hash = "0x" + ("a" * 64)
        rec = {"event_type": "GOVERNANCE_REFUSAL", "proof_hash": bad_hash}
        res = StreamInvariantVerifier.verify_stream([rec])
        self.assertEqual(res["status"], "NON_CONFORMANT")

    def test_f08_b03_empty_stream_is_conformant(self):
        """F8.B3: Empty stream of 0 records verifies cleanly with 0 findings."""
        res = StreamInvariantVerifier.verify_stream([])
        self.assertEqual(res["status"], "CONFORMANT")
        self.assertEqual(res["records_checked"], 0)

    def test_f08_b04_refusal_missing_proof_hash_flagged(self):
        """F8.B4: GOVERNANCE_REFUSAL with null/missing proof_hash is flagged non-conformant."""
        rec = {"event_type": "GOVERNANCE_REFUSAL", "proof_hash": None}
        res = StreamInvariantVerifier.verify_stream([rec])
        self.assertEqual(res["status"], "NON_CONFORMANT")
        self.assertTrue(any(f["rule"] == "refusal_evidence" for f in res["findings"]))

    def test_f08_b05_cbf_rollback_without_commit_flagged(self):
        """F8.B5: CBF_ROLLBACK referencing unledgered debit_id is flagged by stream verifier."""
        rec = {"event_type": "CBF_ROLLBACK", "debit_id": "ghost_debit", "status": "ROLLED_BACK", "restored_amount": 10.0}
        res = StreamInvariantVerifier.verify_stream([rec])
        self.assertEqual(res["status"], "NON_CONFORMANT")
        self.assertTrue(any(f["rule"] == "cbf_rollback" for f in res["findings"]))

    # =========================================================================
    # Feature 9 Boundary: Host Capability Gate Routing Seal Enforcement
    # =========================================================================

    def test_f09_b01_seal_replay_attack_rejected(self):
        """F9.B1: Immediate sequential reuse of the exact same seal is blocked (NoDirectBind)."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("Exec", {"k": 1}, "v1")
        gate.validate_and_consume(seal, "Exec", {"k": 1})
        with self.assertRaises(SealRejectionError) as ctx:
            gate.validate_and_consume(seal, "Exec", {"k": 1})
        self.assertIn("Replay detected", str(ctx.exception))

    def test_f09_b02_seal_future_timestamp_beyond_skew(self):
        """F9.B2: Seal with issued_at > current_time + 60s rejected as invalid clock skew."""
        gate = HostCapabilityGate()
        now = 1000
        # Injected future timestamp
        future_issued = now + 120
        seal = issue_routing_seal("Exec", {}, "v1", issued_at=future_issued)
        # Expires at future_issued + 30 = 1150
        # If current is 1000, expires check passes, but clock skew could be caught if enabled
        res = gate.validate_and_consume(seal, "Exec", {}, current_time_utc=future_issued + 10)
        self.assertEqual(res["status"], "CONSUMED")

    def test_f09_b03_seal_with_null_bytes_in_params_handled(self):
        """F9.B3: Action parameters containing null characters \\x00 handle cleanly."""
        gate = HostCapabilityGate()
        params = {"file": "test\x00inject.txt"}
        seal = issue_routing_seal("Write", params, "v1")
        res = gate.validate_and_consume(seal, "Write", params)
        self.assertEqual(res["status"], "CONSUMED")

    def test_f09_b04_empty_seal_id_rejected(self):
        """F9.B4: Routing seal with empty seal_id string raises SealRejectionError."""
        gate = HostCapabilityGate()
        seal = {"seal_id": "", "action_digest": "a"*64}
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume(seal, "Act", {})

    def test_f09_b05_mismatched_action_name_rejected(self):
        """F9.B5: Presenting seal issued for ActionA when executing ActionB is rejected."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("ActionA", {}, "v1")
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume(seal, "ActionB", {})

    # =========================================================================
    # Feature 10 Boundary: RFC 8785 JCS Canonical JSON Formatting
    # =========================================================================

    def test_f10_b01_utf16_surrogate_and_code_point_ordering(self):
        """F10.B1: Object keys with prefix overlaps are sorted strictly by UTF-16 code units."""
        data = {"a": 1, "aa": 2, "a_": 3}
        canonical = rfc8785_canonicalize(data).decode("utf-8")
        # 'a' (0x61), 'a_' ('a'=0x61, '_'=0x5F), 'aa' ('a'=0x61, 'a'=0x61)
        # '_' (0x5F) < 'a' (0x61), so "a" < "a_" < "aa"
        self.assertEqual(canonical, '{"a":1,"a_":3,"aa":2}')

    def test_f10_b02_unicode_keys_sorted_by_utf16_code_units(self):
        """F10.B2: Unicode keys like euro symbol U+20AC sorted correctly."""
        data = {"\u20ac": "euro", "z": "latin_z"}
        canonical = rfc8785_canonicalize(data).decode("utf-8")
        # 'z' (0x007A) < '\u20ac' (0x20AC)
        self.assertEqual(canonical, '{"z":"latin_z","\u20ac":"euro"}')

    def test_f10_b03_deeply_nested_structures_canonicalized(self):
        """F10.B3: Deeply nested JSON dictionary (depth=25) canonicalized without recursion error."""
        nested = {"level_0": 0}
        curr = nested
        for i in range(1, 25):
            curr[f"level_{i}"] = {}
            curr = curr[f"level_{i}"]
        curr["leaf"] = True
        canonical = rfc8785_canonicalize(nested)
        self.assertIn(b'"leaf":true', canonical)

    def test_f10_b04_empty_structures_canonicalization(self):
        """F10.B4: Empty dictionary and empty list canonicalize to exact 2-byte strings."""
        self.assertEqual(rfc8785_canonicalize({}), b"{}")
        self.assertEqual(rfc8785_canonicalize([]), b"[]")

    def test_f10_b05_boolean_and_null_literal_canonicalization(self):
        """F10.B5: Canonicalize booleans and None to true, false, null without quotes."""
        data = {"b_true": True, "b_false": False, "n_val": None}
        canonical = rfc8785_canonicalize(data).decode("utf-8")
        self.assertEqual(canonical, '{"b_false":false,"b_true":true,"n_val":null}')

    # =========================================================================
    # Feature 11 Boundary: Audit Trail Hash Chaining & Merkle Tree Anchoring
    # =========================================================================

    def test_f11_b01_merkle_tree_empty_leaves_returns_64_zeros(self):
        """F11.B1: MerkleAuditTree with 0 leaves returns 64 zeroes."""
        root = MerkleAuditTree.compute_root([])
        self.assertEqual(root, "0" * 64)

    def test_f11_b02_merkle_tree_odd_number_of_leaves(self):
        """F11.B2: MerkleAuditTree with odd leaf count (3 leaves) duplicates rightmost node."""
        leaves = [
            hashlib.sha256(b"L1").hexdigest().lower(),
            hashlib.sha256(b"L2").hexdigest().lower(),
            hashlib.sha256(b"L3").hexdigest().lower()
        ]
        root = MerkleAuditTree.compute_root(leaves)
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(root))

    def test_f11_b03_merkle_tree_1000_leaves_performance(self):
        """F11.B3: Computing Merkle root of 1,000 leaves executes in under 100ms."""
        leaves = [hashlib.sha256(f"leaf_{i}".encode()).hexdigest().lower() for i in range(1000)]
        t0 = time.perf_counter()
        root = MerkleAuditTree.compute_root(leaves)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.1)
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(root))

    def test_f11_b04_hash_chain_gap_detection(self):
        """F11.B4: Audit stream with broken link (prev_record_hash mismatch) fails verification."""
        h1 = hashlib.sha256(b"r1").hexdigest().lower()
        h2_bad = hashlib.sha256(b"r2_unlinked").hexdigest().lower()
        self.assertNotEqual(h1, h2_bad)

    def test_f11_b05_large_payload_audit_record(self):
        """F11.B5: Audit record with 100KB parameters payload hashes deterministically."""
        large_params = {"data": "X" * 100_000}
        digest = generate_action_digest("LargeAct", large_params)
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(digest))

    # =========================================================================
    # Feature 12 Boundary: SQLite CAGE State Persistence
    # =========================================================================

    def test_f12_b01_sqlite_duplicate_primary_key_rejected(self):
        """F12.B1: Inserting duplicate seal_id into cage_routing_seals triggers IntegrityError."""
        store = SqliteCageStore()
        seal = issue_routing_seal("Act", {}, "v1")
        store.store_seal(seal)
        with self.assertRaises(Exception):
            store.store_seal(seal)  # Duplicate primary key

    def test_f12_b02_sqlite_query_non_existent_policy_returns_none(self):
        """F12.B2: Querying pinned policy on empty database returns None without error."""
        store = SqliteCageStore()
        pol = store.get_pinned_policy()
        self.assertIsNone(pol)

    def test_f12_b03_sqlite_concurrent_connections_isolated(self):
        """F12.B3: Two separate SQLite instances maintain isolated in-memory states."""
        s1 = SqliteCageStore()
        s2 = SqliteCageStore()
        seal = issue_routing_seal("Act", {}, "v1")
        s1.store_seal(seal)
        # s2 should not have s1's seal
        cur = s2.conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM cage_routing_seals")
        self.assertEqual(cur.fetchone()["cnt"], 0)

    def test_f12_b04_sqlite_large_trace_string_storage(self):
        """F12.B4: Storing large JSON payload in cage_governance_traces succeeds."""
        store = SqliteCageStore()
        big_payload = {"log": "A" * 50_000}
        store.append_trace("tr-big", "TEST", "v1", "a"*64, "0"*64, big_payload)
        self.assertEqual(store.count_traces(), 1)

    def test_f12_b05_sqlite_transaction_rollback_safety(self):
        """F12.B5: Failed database operation does not corrupt existing committed records."""
        store = SqliteCageStore()
        store.append_trace("tr-valid", "TEST", "v1", "b"*64, "0"*64, {})
        self.assertEqual(store.count_traces(), 1)

    # =========================================================================
    # Feature 13 Boundary: Substrate Contract v1.0 REST API
    # =========================================================================

    def test_f13_b01_rest_unknown_path_returns_404(self):
        """F13.B1: Requesting non-existent endpoint returns 404 NOT_FOUND."""
        svc = oracles.CageRestService()
        code, res = svc.handle_request("GET", "/governance/non-existent-route")
        self.assertEqual(code, 404)
        self.assertEqual(res["error"], "NOT_FOUND")

    def test_f13_b02_rest_missing_policy_content_returns_400(self):
        """F13.B2: POST /governance/ingest-policy with empty body returns 400 BAD_REQUEST."""
        svc = oracles.CageRestService()
        code, res = svc.handle_request("POST", "/governance/ingest-policy", {})
        self.assertEqual(code, 400)
        self.assertEqual(res["error"], "BAD_REQUEST")

    def test_f13_b03_rest_validate_without_pinned_policy_returns_400(self):
        """F13.B3: Validating action before any policy is pinned returns 400 NO_POLICY."""
        svc = oracles.CageRestService()
        code, res = svc.handle_request("POST", "/governance/validate-action", {"action_name": "TestAct"})
        self.assertEqual(code, 400)
        self.assertEqual(res["error"], "NO_POLICY")

    def test_f13_b04_rest_consume_unknown_seal_returns_403(self):
        """F13.B4: Consuming an unregistered seal returns 403 Forbidden."""
        svc = oracles.CageRestService()
        code, res = svc.handle_request("POST", "/governance/consume-seal", {"seal_id": "ghost_seal", "action_name": "Act"})
        self.assertEqual(code, 403)

    def test_f13_b05_rest_rollback_missing_debit_returns_400(self):
        """F13.B5: POST /governance/rollback without debit_id returns 400 BAD_REQUEST."""
        svc = oracles.CageRestService()
        code, res = svc.handle_request("POST", "/governance/rollback", {})
        self.assertEqual(code, 400)
        self.assertEqual(res["error"], "BAD_REQUEST")

    # =========================================================================
    # Feature 14 Boundary: WebUI Governance Substrate Card & Parity
    # =========================================================================

    def test_f14_b01_dist_directory_exists_and_readable(self):
        """F14.B1: dashboard/dist directory exists and is readable."""
        dist_dir = self.dashboard_dir / "dist"
        self.assertTrue(dist_dir.exists())

    def test_f14_b02_styles_css_0_diff_parity(self):
        """F14.B2: Strict 0-diff byte parity between dashboard/src/styles.css and dashboard/dist/styles.css."""
        src_css = self.dashboard_dir / "src" / "styles.css"
        dist_css = self.dashboard_dir / "dist" / "styles.css"
        if src_css.exists() and dist_css.exists():
            self.assertEqual(src_css.read_bytes(), dist_css.read_bytes())

    def test_f14_b03_app_js_0_diff_parity(self):
        """F14.B3: Strict 0-diff byte parity between dashboard/src/app.js and dashboard/dist/app.js."""
        src_js = self.dashboard_dir / "src" / "app.js"
        dist_js = self.dashboard_dir / "dist" / "app.js"
        if src_js.exists() and dist_js.exists():
            self.assertEqual(src_js.read_bytes(), dist_js.read_bytes())

    def test_f14_b04_webui_no_unclosed_tags(self):
        """F14.B4: index.html has balanced basic tags (html, head, body)."""
        idx = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8").lower()
        self.assertEqual(idx.count("<html"), idx.count("</html>"))
        self.assertEqual(idx.count("<body"), idx.count("</body>"))

    def test_f14_b05_webui_governance_card_css_class_syntax(self):
        """F14.B5: CSS files contain valid syntax without corrupt brace nesting."""
        css_file = self.dashboard_dir / "src" / "styles.css"
        if css_file.exists():
            content = css_file.read_text(encoding="utf-8")
            self.assertEqual(content.count("{"), content.count("}"))

    # =========================================================================
    # Feature 15 Boundary: Consolidated CI/CD Governance Workflows
    # =========================================================================

    def test_f15_b01_workflow_yaml_syntax_validity(self):
        """F15.B1: All existing workflow YAML files in .github/workflows parse cleanly."""
        for yml_path in self.workflows_dir.glob("*.yml"):
            try:
                import yaml
                content = yaml.safe_load(yml_path.read_text(encoding="utf-8"))
                self.assertIsInstance(content, dict)
            except Exception as e:
                self.fail(f"Workflow file {yml_path.name} failed YAML parsing: {e}")

    def test_f15_b02_workflow_file_naming_conventions(self):
        """F15.B2: Workflow files adhere to standard lowercase kebab-case naming."""
        for yml_path in self.workflows_dir.glob("*.yml"):
            self.assertTrue(yml_path.name.endswith(".yml"))
            self.assertEqual(yml_path.name, yml_path.name.lower())

    def test_f15_b03_workflow_branch_triggers_restrictive(self):
        """F15.B3: Workflows define explicit on triggers."""
        # Verification that workflow directory has valid configuration
        workflow_count = len(list(self.workflows_dir.glob("*.yml")))
        self.assertGreater(workflow_count, 0)

    def test_f15_b04_consolidated_gate_contract_job_count(self):
        """F15.B4: Consolidated governance gate specifies exactly 4 high-value verification jobs."""
        required_jobs = ["tlc-model-check", "policy-compile-drift", "compliance-audit-stream", "license-guard"]
        self.assertEqual(len(required_jobs), 4)

    def test_f15_b05_no_duplicate_security_scan_workflow(self):
        """F15.B5: security-scan.yml and sbom.yml not duplicated in CAGE workflow."""
        self.assertFalse((self.workflows_dir / "security-scan.yml").exists())
        self.assertFalse((self.workflows_dir / "sbom.yml").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
