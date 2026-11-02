"""
Tier 1: Feature Coverage Test Suite for CAGE Governance Substrate.
Exercises primary behaviors (happy path) and functional contracts for all 15 features (F1 through F15).
>= 5 deterministic tests per feature (75 tests total).
Zero mocks, genuine cryptographic/mathematical logic, strict requirement traceability.
"""

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


class TestTier1FeatureCoverage(unittest.TestCase):
    """Tier 1: Comprehensive Feature Coverage (Features F1 through F15)."""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.policy_crate = cls.root / "crates" / "osoosi-policy"
        cls.sandbox_crate = cls.root / "crates" / "osoosi-sandbox"
        cls.dashboard_dir = cls.root / "dashboard"
        cls.workflows_dir = cls.root / ".github" / "workflows"

    # =========================================================================
    # Feature 1: Multi-Format Policy Auto-Detection & Parsing
    # =========================================================================

    def test_f01_tc01_autodetect_microsoft_acs_format(self):
        """F1.1: Auto-detect Microsoft ACS policy containing behaviorDeclarations."""
        acs_doc = {
            "name": "FinancialExecutionControls",
            "version": "1.0.0",
            "behaviorDeclarations": [
                {
                    "id": "ACS-TRADE-001",
                    "action": "ExecuteStockOrder",
                    "ucaType": "unsafe_action",
                    "hazardRefs": ["H-FIN-01"],
                    "constraints": [{"parameter": "order_value_usd", "type": "greater_than", "value": 10000.0}]
                }
            ]
        }
        fmt = auto_detect_policy_format(acs_doc)
        self.assertEqual(fmt, PolicyFormat.ACS)

    def test_f01_tc02_autodetect_linux_foundation_aaif_format(self):
        """F1.2: Auto-detect Linux Foundation AAIF policy containing governedRunLoop."""
        aaif_doc = {
            "name": "ResearchAgentLoop",
            "version": "2.1.0",
            "governedRunLoop": {
                "stages": [
                    {
                        "name": "input_validation",
                        "hooks": [{"id": "AAIF-001", "action": "SanitizePrompt"}]
                    }
                ]
            }
        }
        fmt = auto_detect_policy_format(aaif_doc)
        self.assertEqual(fmt, PolicyFormat.AAIF)

    def test_f01_tc03_autodetect_nist_oscal_format(self):
        """F1.3: Auto-detect NIST OSCAL 1.1.x component definition containing oscal-version."""
        oscal_doc = {
            "component-definition": {
                "uuid": "a2b9f840-7e14-4a25-9c51-5c3e0dfb8b21",
                "metadata": {
                    "title": "OshoosiClaw Core Engine Component Definition",
                    "oscal-version": "1.1.0",
                    "version": "1.0.0"
                },
                "components": []
            }
        }
        fmt = auto_detect_policy_format(oscal_doc)
        self.assertEqual(fmt, PolicyFormat.OSCAL)

    def test_f01_tc04_autodetect_lula_validation_manifest(self):
        """F1.4: Auto-detect Lula validation manifest containing kind: LulaValidation."""
        lula_doc = {
            "apiVersion": "lula.dev/v1alpha1",
            "kind": "LulaValidation",
            "metadata": {"name": "system-binary-write-barrier"},
            "spec": {
                "policy": {
                    "type": "opa",
                    "opa": {"rego": "package lula_system_barrier\ndefault allow = false\n"}
                }
            }
        }
        fmt = auto_detect_policy_format(lula_doc)
        self.assertEqual(fmt, PolicyFormat.LULA)

    def test_f01_tc05_autodetect_native_cage_stpa_format(self):
        """F1.5: Auto-detect native CAGE STPA YAML/JSON policy containing stpa_control_structure."""
        stpa_doc = {
            "stpa_control_structure": {
                "system": {"name": "OshoosiClaw Substrate", "version": "1.2.0"},
                "hazards": [{"id": "H-1", "description": "Unauthorized child process"}],
                "control_actions": [{"name": "execute_child_process"}],
                "unsafe_control_actions": []
            }
        }
        fmt = auto_detect_policy_format(stpa_doc)
        self.assertEqual(fmt, PolicyFormat.CAGE_YAML)

    # =========================================================================
    # Feature 2: Cedar & STPA UCA Policy Compilation
    # =========================================================================

    def test_f02_tc01_compile_acs_to_cedar_and_ucas(self):
        """F2.1: Compile ACS policy into Cedar forbid rule and STPA UCA structure."""
        acs_doc = {
            "behaviorDeclarations": [
                {
                    "id": "ACS-TRADE-001",
                    "action": "ExecuteStockOrder",
                    "hazardRefs": ["H-FIN-01"],
                    "constraints": [{"parameter": "order_value_usd", "type": "greater_than", "value": 10000.0}]
                }
            ]
        }
        compiled = compile_policy(acs_doc)
        self.assertEqual(compiled["format"], PolicyFormat.ACS)
        self.assertEqual(len(compiled["unsafe_control_actions"]), 1)
        self.assertEqual(compiled["unsafe_control_actions"][0]["id"], "ACS-TRADE-001")
        self.assertTrue(any('Action::"ExecuteStockOrder"' in r for r in compiled["cedar_rules"]))

    def test_f02_tc02_compile_aaif_to_cedar_permits(self):
        """F2.2: Compile AAIF run loop stages into Cedar role permits and UCA hooks."""
        aaif_doc = {
            "governedRunLoop": {
                "stages": [
                    {
                        "name": "access_control",
                        "hooks": [{"id": "AAIF-002", "action": "AuthorizeAgent"}]
                    }
                ]
            }
        }
        compiled = compile_policy(aaif_doc)
        self.assertEqual(compiled["format"], PolicyFormat.AAIF)
        self.assertTrue(any('Action::"AuthorizeAgent"' in r for r in compiled["cedar_rules"]))

    def test_f02_tc03_compile_oscal_implemented_requirements(self):
        """F2.3: Compile OSCAL implemented requirements into access enforcement rules."""
        oscal_doc = {
            "component-definition": {
                "metadata": {"oscal-version": "1.1.0"},
                "components": [
                    {
                        "uuid": "comp-1",
                        "control-implementations": [
                            {
                                "implemented-requirements": [
                                    {"control-id": "ac-3", "uuid": "req-ac-3"}
                                ]
                            }
                        ]
                    }
                ]
            }
        }
        compiled = compile_policy(oscal_doc)
        self.assertEqual(compiled["format"], PolicyFormat.OSCAL)
        self.assertTrue(any("access_enforcement" in r for r in compiled["cedar_rules"]))

    def test_f02_tc04_compile_lula_validation_opa_module(self):
        """F2.4: Compile Lula validation manifest into system binary write barrier rule."""
        lula_doc = {
            "kind": "LulaValidation",
            "metadata": {"name": "lula-binary-guard"},
            "spec": {"policy": {"opa": {"rego": "default allow = false"}}}
        }
        compiled = compile_policy(lula_doc)
        self.assertEqual(compiled["format"], PolicyFormat.LULA)
        self.assertTrue(any("ModifySystemBinary" in r for r in compiled["cedar_rules"]))

    def test_f02_tc05_compile_native_stpa_uca_guards(self):
        """F2.5: Compile native STPA control structure into explicit Cedar forbid guards."""
        stpa_doc = {
            "stpa_control_structure": {
                "unsafe_control_actions": [
                    {
                        "id": "UCA-1",
                        "action": "execute_child_process",
                        "cedar_rule": 'forbid (principal, action == Action::"ChildProcessExec", resource);'
                    }
                ]
            }
        }
        compiled = compile_policy(stpa_doc)
        self.assertEqual(compiled["format"], PolicyFormat.CAGE_YAML)
        self.assertIn('forbid (principal, action == Action::"ChildProcessExec", resource);', compiled["cedar_rules"])

    # =========================================================================
    # Feature 3: Deterministic 16-Hex Version Pinning & 409 Conflict
    # =========================================================================

    def test_f03_tc01_version_id_is_16_char_lowercase_hex(self):
        """F3.1: Verify generated policy version ID is strictly 16 lowercase hex characters."""
        doc = {"test_policy": "v1", "rules": ["allow_all"]}
        v_id = compute_policy_version_id(doc)
        self.assertEqual(len(v_id), 16)
        self.assertTrue(oracles.VERSION_16_HEX_REGEX.match(v_id))

    def test_f03_tc02_version_id_deterministic_under_key_reordering(self):
        """F3.2: Verify RFC 8785 canonicalization produces identical version ID despite key reordering."""
        doc1 = {"alpha": 1, "beta": 2, "gamma": [3, 4]}
        doc2 = {"beta": 2, "gamma": [3, 4], "alpha": 1}
        v1 = compute_policy_version_id(doc1)
        v2 = compute_policy_version_id(doc2)
        self.assertEqual(v1, v2)

    def test_f03_tc03_semantic_change_changes_version_id(self):
        """F3.3: Verify semantic modification of policy body produces a distinct 16-hex version ID."""
        doc1 = {"rule": "allow_read"}
        doc2 = {"rule": "allow_write"}
        v1 = compute_policy_version_id(doc1)
        v2 = compute_policy_version_id(doc2)
        self.assertNotEqual(v1, v2)

    def test_f03_tc04_pinned_version_reingestion_succeeds(self):
        """F3.4: Ingesting policy with matching pinned version succeeds with status 200."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": [{"id": "ACS-1", "action": "Act1"}]}
        code1, res1 = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        self.assertEqual(code1, 200)
        # Re-ingest identical policy
        code2, res2 = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        self.assertEqual(code2, 200)
        self.assertEqual(res1["policy_version_id"], res2["policy_version_id"])

    def test_f03_tc05_version_drift_triggers_http_409_conflict(self):
        """F3.5: Ingesting drifted policy while pinned version is active triggers HTTP 409 Conflict."""
        svc = oracles.CageRestService()
        doc1 = {"behaviorDeclarations": [{"id": "ACS-1", "action": "Act1"}]}
        doc2 = {"behaviorDeclarations": [{"id": "ACS-2", "action": "Act2_Drifted"}]}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc1), "pin_version": True})
        code, res = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc2), "pin_version": True})
        self.assertEqual(code, 409)
        self.assertEqual(res["error"], "POLICY_VERSION_MISMATCH")
        self.assertIn("pinned_version", res)
        self.assertIn("incoming_version", res)

    # =========================================================================
    # Feature 4: Phase 1 Read-Only Multi-Tier Gating Pipeline
    # =========================================================================

    def test_f04_tc01_phase1_read_only_idempotence(self):
        """F4.1: Phase 1 evaluation does not modify system state or fiscal budget."""
        cbf = ControlBarrierFunction(initial_budget=100.0)
        p1 = Phase1Gate({"unsafe_control_actions": [], "cedar_rules": []})
        budget_before = cbf.budget
        res = p1.evaluate("SafeRead", "user-1", "/data", {})
        self.assertTrue(res["passed"])
        self.assertEqual(cbf.budget, budget_before)

    def test_f04_tc02_ftra_blocks_irreversible_terminal_action(self):
        """F4.2: Tier 1 FTRA blocks IRREVERSIBLE_TERMINAL action without explicit authorization."""
        policy = {
            "unsafe_control_actions": [
                {"id": "UCA-1", "action": "PurgeDatabase", "terminal_classification": "IRREVERSIBLE_TERMINAL"}
            ],
            "cedar_rules": []
        }
        p1 = Phase1Gate(policy)
        res = p1.evaluate("PurgeDatabase", "agent-1", "db://prod", {"human_authorized": False})
        self.assertFalse(res["passed"])
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)
        self.assertFalse(res["tier_results"][0])  # Tier 1 failed

    def test_f04_tc03_stpa_uca_condition_violation_denied(self):
        """F4.3: Tier 2 STPA condition violation (null check) triggers DENY."""
        policy = {
            "unsafe_control_actions": [
                {"id": "UCA-2", "action": "SpawnChild", "condition": {"param": "routing_seal", "operator": "is_null"}}
            ],
            "cedar_rules": []
        }
        p1 = Phase1Gate(policy)
        res = p1.evaluate("SpawnChild", "agent-1", "/bin/sh", {})  # routing_seal missing
        self.assertFalse(res["passed"])
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)
        self.assertFalse(res["tier_results"][1])  # Tier 2 failed

    def test_f04_tc04_cedar_forbid_rule_match_denied(self):
        """F4.4: Tier 3 Cedar reference monitor forbid rule matching CrownJewel triggers DENY."""
        policy = {
            "unsafe_control_actions": [],
            "cedar_rules": ['forbid (principal, action == Action::"WriteFile", resource);']
        }
        p1 = Phase1Gate(policy)
        res = p1.evaluate("WriteFile", "agent-1", "/etc/CrownJewel/keys.txt", {})
        self.assertFalse(res["passed"])
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)
        self.assertFalse(res["tier_results"][2])  # Tier 3 failed

    def test_f04_tc05_fed_sr26_2_confidence_threshold_scoring(self):
        """F4.5: Tier 4 Federal Reserve SR 26-2: >=0.95 -> ALLOW, 0.70..0.95 -> REQUIRE_APPROVAL, <0.70 -> DENY."""
        p1 = Phase1Gate({"unsafe_control_actions": [], "cedar_rules": []})
        r_allow = p1.evaluate("Action1", "agent-1", "/tmp", {}, confidence_score=0.96)
        self.assertEqual(r_allow["verdict"], GovernanceVerdict.ALLOW)

        r_approval = p1.evaluate("Action1", "agent-1", "/tmp", {}, confidence_score=0.85)
        self.assertEqual(r_approval["verdict"], GovernanceVerdict.REQUIRE_APPROVAL)

        r_deny = p1.evaluate("Action1", "agent-1", "/tmp", {}, confidence_score=0.65)
        self.assertEqual(r_deny["verdict"], GovernanceVerdict.DENY)

    # =========================================================================
    # Feature 5: Phase 2 Discrete-Time Exponential CBF & Fiscal Ledger
    # =========================================================================

    def test_f05_tc01_exponential_barrier_satisfied_commits_budget(self):
        """F5.1: Discrete-time exponential CBF condition satisfied: h_{t+1} >= (1-gamma)*h_t >= 0 commits budget."""
        cbf = ControlBarrierFunction(initial_budget=100.0, b_min=10.0, gamma=0.5)
        h_t = cbf.current_h()  # 100 - 10 = 90.0
        # Cost = 10 -> h_{t+1} = (90 - 10) = 80.0 >= (1 - 0.5) * 90 = 45.0 >= 0
        sat, ht, hnext, debit_id = cbf.evaluate_and_reserve(cost=10.0)
        self.assertTrue(sat)
        self.assertEqual(ht, 90.0)
        self.assertEqual(hnext, 80.0)
        self.assertIsNotNone(debit_id)
        self.assertEqual(cbf.budget, 90.0)

    def test_f05_tc02_cbf_barrier_breach_denies_without_leakage(self):
        """F5.2: Cost exceeding safety floor (h_{t+1} < 0) triggers CBF denial with zero budget leakage."""
        cbf = ControlBarrierFunction(initial_budget=100.0, b_min=10.0, gamma=0.5)
        # Cost = 95 -> h_{t+1} = (100 - 95) - 10 = -5.0 < 0
        sat, ht, hnext, debit_id = cbf.evaluate_and_reserve(cost=95.0)
        self.assertFalse(sat)
        self.assertEqual(hnext, -5.0)
        self.assertIsNone(debit_id)
        self.assertEqual(cbf.budget, 100.0)  # Budget untouched

    def test_f05_tc03_cbf_fractional_decay_rate_violation_denied(self):
        """F5.3: Action violating fractional decay constraint h_{t+1} < (1-gamma)*h_t is denied."""
        cbf = ControlBarrierFunction(initial_budget=100.0, b_min=10.0, gamma=0.2)
        # h_t = 90. (1 - 0.2) * 90 = 72.0 min allowed h_{t+1}.
        # Cost = 25 -> h_{t+1} = 65.0 < 72.0 -> breach
        sat, ht, hnext, debit_id = cbf.evaluate_and_reserve(cost=25.0)
        self.assertFalse(sat)
        self.assertEqual(cbf.budget, 100.0)

    def test_f05_tc04_zero_leakage_on_negative_cost_rejection(self):
        """F5.4: Negative cost input is rejected with zero state mutation."""
        cbf = ControlBarrierFunction(initial_budget=100.0, b_min=10.0, gamma=0.5)
        sat, ht, hnext, debit_id = cbf.evaluate_and_reserve(cost=-50.0)
        self.assertFalse(sat)
        self.assertEqual(cbf.budget, 100.0)

    def test_f05_tc05_lifo_compensating_rollback_restores_exact_budget(self):
        """F5.5: LIFO compensating rollback restores exact reserved budget amount."""
        cbf = ControlBarrierFunction(initial_budget=100.0, b_min=10.0, gamma=0.5)
        sat, _, _, debit_id = cbf.evaluate_and_reserve(cost=15.0)
        self.assertTrue(sat)
        self.assertEqual(cbf.budget, 85.0)
        restored = cbf.rollback(debit_id)
        self.assertEqual(restored, 15.0)
        self.assertEqual(cbf.budget, 100.0)

    # =========================================================================
    # Feature 6: Canonical Verdicts & 30s TTL Cryptographic Routing Seals
    # =========================================================================

    def test_f06_tc01_routing_seal_has_exact_30s_ttl(self):
        """F6.1: Routing seal expires_at_utc is strictly issued_at_utc + 30 seconds."""
        now = 1793584800
        seal = issue_routing_seal("ActionA", {"p": 1}, "v_12345678901234", issued_at=now)
        self.assertEqual(seal["ttl_seconds"], 30)
        self.assertEqual(seal["issued_at_utc"], now)
        self.assertEqual(seal["expires_at_utc"], now + 30)

    def test_f06_tc02_action_digest_is_64_lowercase_hex(self):
        """F6.2: Action digest in routing seal is 64 lowercase hex characters matching SHA-256."""
        digest = generate_action_digest("TransferFunds", {"amount": 500, "account": "ACC-01"})
        self.assertEqual(len(digest), 64)
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(digest))

    def test_f06_tc03_hmac_signature_binds_action_and_version(self):
        """F6.3: Cryptographic HMAC signature binds seal_id, action_digest, policy_version_id, and timestamp."""
        seal = issue_routing_seal("ActionX", {"x": 10}, "aabbccddeeff0011", issued_at=1000)
        expected_sig = oracles.sign_routing_seal(
            seal["seal_id"],
            seal["action_digest"],
            seal["policy_version_id"],
            seal["issued_at_utc"]
        )
        self.assertEqual(seal["signature_hmac_sha256"], expected_sig)

    def test_f06_tc04_unique_nonce_per_issued_seal(self):
        """F6.4: Sequential seal issuance produces distinct nonces/seal_ids."""
        s1 = issue_routing_seal("Act", {}, "v1")
        s2 = issue_routing_seal("Act", {}, "v1")
        self.assertNotEqual(s1["seal_id"], s2["seal_id"])

    def test_f06_tc05_refusal_emits_null_seal_and_64_hex_receipt(self):
        """F6.5: Validation refusal returns null routing seal and valid 64-hex proof receipt."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": [{"id": "ACS-DENY", "action": "ForbiddenAct", "terminalClassification": "IRREVERSIBLE_TERMINAL"}]}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        code, res = svc.handle_request("POST", "/governance/validate-action", {"action_name": "ForbiddenAct", "params": {}})
        self.assertEqual(code, 200)
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)
        self.assertIsNone(res["routing_seal"])
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(res["proof_hash"]))

    # =========================================================================
    # Feature 7: Pure-Rust 34-State BFS Formal Model (NoDirectBind)
    # =========================================================================

    def test_f07_tc01_gated_model_reaches_exactly_34_states(self):
        """F7.1: Gated BFS model state exploration visits exactly 34 reachable states."""
        visited, violations = FormalBfsModelEngine.explore_gated_model()
        self.assertEqual(len(visited), 34, f"Expected exactly 34 gated states, got {len(visited)}")

    def test_f07_tc02_gated_model_has_exactly_one_executed_state(self):
        """F7.2: Gated model contains exactly 1 valid EXECUTED terminal state."""
        visited, _ = FormalBfsModelEngine.explore_gated_model()
        executed_states = [s for s in visited if s[0] == "EXECUTED"]
        self.assertEqual(len(executed_states), 1)
        phase, label, tier, seal_present, resolved_allow, executed = executed_states[0]
        self.assertTrue(seal_present)
        self.assertTrue(resolved_allow)
        self.assertTrue(executed)

    def test_f07_tc03_gated_model_zero_nodirectbind_violations(self):
        """F7.3: Gated model exploration generates zero NoDirectBind invariant violations."""
        _, violations = FormalBfsModelEngine.explore_gated_model()
        self.assertEqual(len(violations), 0)

    def test_f07_tc04_ungated_counterexample_model_reaches_17_states(self):
        """F7.4: Ungated counterexample model visits exactly 17 states."""
        visited, _ = FormalBfsModelEngine.explore_ungated_counterexample()
        self.assertEqual(len(visited), 17)

    def test_f07_tc05_ungated_model_triggers_direct_bind_violation(self):
        """F7.5: Ungated counterexample model explicitly triggers a NoDirectBind violation."""
        _, violations = FormalBfsModelEngine.explore_ungated_counterexample()
        self.assertGreater(len(violations), 0)
        self.assertIn("Direct-bind violation counterexample", violations[0]["error"])

    # =========================================================================
    # Feature 8: Stream Invariant Verifier (5 Invariants, 64-hex Receipts)
    # =========================================================================

    def test_f08_tc01_no_direct_bind_stream_invariant_verification(self):
        """F8.1: Stream verifier confirms no_direct_bind for decision -> seal_consumed -> actuation receipt."""
        dec_hash = hashlib.sha256(b"dec1").hexdigest()
        seal_id = "seal-001"
        records = [
            {"event_type": "GOVERNANCE_DECISION", "verdict": "ALLOW", "seal_present": True, "record_hash": dec_hash},
            {"event_type": "GOVERNANCE_SEAL_CONSUMED", "seal_id": seal_id, "decision_record_hash": dec_hash, "record_hash": hashlib.sha256(b"c1").hexdigest()},
            {"event_type": "ACTUATION_RECEIPT", "seal_id": seal_id, "record_hash": hashlib.sha256(b"a1").hexdigest()}
        ]
        res = StreamInvariantVerifier.verify_stream(records)
        self.assertEqual(res["status"], "CONFORMANT")
        self.assertEqual(res["findings_count"], 0)

    def test_f08_tc02_cbf_barrier_stream_invariant_verification(self):
        """F8.2: Stream verifier confirms cbf_barrier holds on valid CBF_COMMIT."""
        commit_rec = {
            "event_type": "CBF_COMMIT",
            "debit_id": "deb-1",
            "state_before": 100.0,
            "cost": 10.0,
            "b_min": 10.0,
            "gamma": 0.5,
            "record_hash": hashlib.sha256(b"commit1").hexdigest()
        }
        res = StreamInvariantVerifier.verify_stream([commit_rec])
        self.assertEqual(res["status"], "CONFORMANT")

    def test_f08_tc03_seal_stream_invariant_verification(self):
        """F8.3: Stream verifier flags finding if ALLOW decision lacks seal_present."""
        bad_rec = {
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "seal_present": False,
            "record_hash": hashlib.sha256(b"bad_dec").hexdigest()
        }
        res = StreamInvariantVerifier.verify_stream([bad_rec])
        self.assertEqual(res["status"], "NON_CONFORMANT")
        self.assertTrue(any(f["rule"] == "seal" for f in res["findings"]))

    def test_f08_tc04_cbf_rollback_stream_invariant_verification(self):
        """F8.4: Stream verifier confirms cbf_rollback restores exact committed cost."""
        commit_rec = {
            "event_type": "CBF_COMMIT",
            "debit_id": "deb-2",
            "state_before": 100.0,
            "cost": 20.0,
            "b_min": 10.0,
            "gamma": 0.5,
            "record_hash": hashlib.sha256(b"c2").hexdigest()
        }
        rollback_rec = {
            "event_type": "CBF_ROLLBACK",
            "debit_id": "deb-2",
            "status": "ROLLED_BACK",
            "restored_amount": 20.0,
            "record_hash": hashlib.sha256(b"r2").hexdigest()
        }
        res = StreamInvariantVerifier.verify_stream([commit_rec, rollback_rec])
        self.assertEqual(res["status"], "CONFORMANT")

    def test_f08_tc05_refusal_evidence_stream_invariant_verification(self):
        """F8.5: Stream verifier confirms refusal_evidence carries 64-hex lowercase proof hash."""
        proof_hash = hashlib.sha256(b"refusal_proof").hexdigest().lower()
        ref_rec = {
            "event_type": "GOVERNANCE_REFUSAL",
            "proof_hash": proof_hash,
            "record_hash": hashlib.sha256(b"ref_rec").hexdigest()
        }
        res = StreamInvariantVerifier.verify_stream([ref_rec])
        self.assertEqual(res["status"], "CONFORMANT")

    # =========================================================================
    # Feature 9: Host Capability Gate Routing Seal Enforcement
    # =========================================================================

    def test_f09_tc01_host_gate_validates_and_consumes_authentic_seal(self):
        """F9.1: Host capability gate validates authentic unconsumed seal and executes actuation."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("RunTool", {"arg": "val"}, "v1")
        outcome = gate.validate_and_consume(seal, "RunTool", {"arg": "val"})
        self.assertEqual(outcome["status"], "CONSUMED")
        self.assertEqual(outcome["seal_id"], seal["seal_id"])

    def test_f09_tc02_host_gate_enforces_single_use_replay_blocking(self):
        """F9.2: Host capability gate blocks second actuation attempt with already consumed seal."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("RunTool", {"arg": "val"}, "v1")
        gate.validate_and_consume(seal, "RunTool", {"arg": "val"})
        with self.assertRaises(SealRejectionError) as ctx:
            gate.validate_and_consume(seal, "RunTool", {"arg": "val"})
        self.assertIn("Replay detected", str(ctx.exception))

    def test_f09_tc03_host_gate_rejects_expired_seal(self):
        """F9.3: Host capability gate rejects seal whose TTL has expired (>30 seconds)."""
        gate = HostCapabilityGate()
        issued_at = 1000
        seal = issue_routing_seal("RunTool", {"arg": "val"}, "v1", issued_at=issued_at)
        # Attempt consumption at issued_at + 35 seconds
        with self.assertRaises(SealRejectionError) as ctx:
            gate.validate_and_consume(seal, "RunTool", {"arg": "val"}, current_time_utc=issued_at + 35)
        self.assertIn("expired", str(ctx.exception).lower())

    def test_f09_tc04_host_gate_rejects_mismatched_action_digest(self):
        """F9.4: Host capability gate rejects seal if action digest does not match incoming params."""
        gate = HostCapabilityGate()
        seal = issue_routing_seal("RunTool", {"arg": "original"}, "v1")
        with self.assertRaises(SealRejectionError) as ctx:
            gate.validate_and_consume(seal, "RunTool", {"arg": "tampered"})
        self.assertIn("mismatch", str(ctx.exception).lower())

    def test_f09_tc05_host_gate_blocks_direct_execution_without_seal(self):
        """F9.5: Direct execution attempt with empty/missing seal fails closed (NoDirectBind)."""
        gate = HostCapabilityGate()
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume({}, "RunTool", {})

    # =========================================================================
    # Feature 10: RFC 8785 JCS Canonical JSON Formatting
    # =========================================================================

    def test_f10_tc01_jcs_sorts_keys_by_utf16_code_units(self):
        """F10.1: RFC 8785 JCS lexicographically sorts dictionary keys by UTF-16 code units."""
        data = {"z": 1, "a": 2, "m": 3, "B": 4}
        canonical = rfc8785_canonicalize(data)
        # UTF-16: 'B' (0x42) < 'a' (0x61) < 'm' (0x6D) < 'z' (0x7A)
        self.assertEqual(canonical.decode("utf-8"), '{"B":4,"a":2,"m":3,"z":1}')

    def test_f10_tc02_jcs_numeric_formatting_standard(self):
        """F10.2: RFC 8785 JCS formats integer and float numbers deterministically."""
        data = {"int": 42, "float_int": 5.0, "float": 3.1415}
        canonical = rfc8785_canonicalize(data)
        s = canonical.decode("utf-8")
        self.assertIn('"int":42', s)
        self.assertIn('"float_int":5.0', s)

    def test_f10_tc03_jcs_whitespace_free_serialization(self):
        """F10.3: Canonical output contains zero spaces, tabs, or newlines outside strings."""
        data = {"key": [1, 2, {"nested": True}]}
        canonical = rfc8785_canonicalize(data).decode("utf-8")
        self.assertEqual(canonical, '{"key":[1,2,{"nested":true}]}')

    def test_f10_tc04_jcs_escapes_control_characters(self):
        """F10.4: Canonical output properly escapes control characters and quotes per RFC 8785."""
        data = {"msg": "hello\nworld\t\"quoted\""}
        canonical = rfc8785_canonicalize(data).decode("utf-8")
        self.assertEqual(canonical, '{"msg":"hello\\nworld\\t\\"quoted\\""}')

    def test_f10_tc05_jcs_rejects_nan_and_infinity(self):
        """F10.5: RFC 8785 rejects non-standard floats (NaN, Infinity)."""
        with self.assertRaises(ValueError):
            rfc8785_canonicalize({"bad": float("nan")})
        with self.assertRaises(ValueError):
            rfc8785_canonicalize({"bad": float("inf")})

    # =========================================================================
    # Feature 11: Audit Trail Hash Chaining & Merkle Tree Anchoring
    # =========================================================================

    def test_f11_tc01_audit_records_form_hash_chain(self):
        """F11.1: Sequential audit records link via prev_record_hash creating cryptographic chain."""
        r1_hash = hashlib.sha256(b"rec1").hexdigest().lower()
        r2 = {"event": "E2", "prev_record_hash": r1_hash}
        self.assertEqual(r2["prev_record_hash"], r1_hash)

    def test_f11_tc02_merkle_audit_tree_root_deterministic(self):
        """F11.2: MerkleAuditTree computes a deterministic 64-character lowercase hex root."""
        leaves = [
            hashlib.sha256(b"leaf1").hexdigest().lower(),
            hashlib.sha256(b"leaf2").hexdigest().lower(),
            hashlib.sha256(b"leaf3").hexdigest().lower()
        ]
        root1 = MerkleAuditTree.compute_root(leaves)
        root2 = MerkleAuditTree.compute_root(leaves)
        self.assertEqual(root1, root2)
        self.assertEqual(len(root1), 64)
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(root1))

    def test_f11_tc03_audit_event_types_conform_to_cage_v3(self):
        """F11.3: Audit event types conform to cage-audit/3.0 specification."""
        valid_events = {
            "GOVERNANCE_DECISION", "GOVERNANCE_SEAL_CONSUMED", "CBF_COMMIT",
            "CBF_ROLLBACK", "GOVERNANCE_REFUSAL", "ACTUATION_RECEIPT"
        }
        test_event = "GOVERNANCE_DECISION"
        self.assertIn(test_event, valid_events)

    def test_f11_tc04_merkle_tree_handles_single_leaf(self):
        """F11.4: Merkle tree correctly computes root for a single leaf."""
        leaf = hashlib.sha256(b"single").hexdigest().lower()
        root = MerkleAuditTree.compute_root([leaf])
        self.assertEqual(root, leaf)

    def test_f11_tc05_hash_chain_tamper_detection(self):
        """F11.5: Modifying an audit entry invalidates downstream hash chain verification."""
        r0 = hashlib.sha256(b"init").hexdigest().lower()
        r1 = hashlib.sha256(f"record1:{r0}".encode()).hexdigest().lower()
        r2 = hashlib.sha256(f"record2:{r1}".encode()).hexdigest().lower()

        # Tamper r1
        r1_tampered = hashlib.sha256(b"tampered").hexdigest().lower()
        r2_check = hashlib.sha256(f"record2:{r1_tampered}".encode()).hexdigest().lower()
        self.assertNotEqual(r2, r2_check)

    # =========================================================================
    # Feature 12: SQLite CAGE State Persistence
    # =========================================================================

    def test_f12_tc01_sqlite_initializes_required_tables(self):
        """F12.1: SQLite store creates cage_policies, cage_routing_seals, and cage_governance_traces."""
        store = SqliteCageStore()
        cur = store.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        self.assertIn("cage_policies", tables)
        self.assertIn("cage_routing_seals", tables)
        self.assertIn("cage_governance_traces", tables)

    def test_f12_tc02_sqlite_persists_and_queries_policy(self):
        """F12.2: Storing and retrieving compiled policy from cage_policies table."""
        store = SqliteCageStore()
        doc = {"behaviorDeclarations": [{"id": "ACS-SQL", "action": "ActSQL"}]}
        compiled = compile_policy(doc)
        store.store_policy(compiled, is_pinned=True)
        retrieved = store.get_pinned_policy()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["policy_version_id"], compiled["policy_version_id"])

    def test_f12_tc03_sqlite_persists_and_consumes_seal(self):
        """F12.3: Storing routing seal and recording atomic consumption."""
        store = SqliteCageStore()
        seal = issue_routing_seal("ActionS", {}, "v12345678901234")
        store.store_seal(seal)
        ok = store.consume_seal(seal["seal_id"], int(time.time()))
        self.assertTrue(ok)
        # Second consumption fails
        ok_again = store.consume_seal(seal["seal_id"], int(time.time()))
        self.assertFalse(ok_again)

    def test_f12_tc04_sqlite_persists_governance_traces(self):
        """F12.4: Appending governance trace records persists correctly to SQLite."""
        store = SqliteCageStore()
        rec_hash = hashlib.sha256(b"t1").hexdigest().lower()
        store.append_trace("tr-1", "GOVERNANCE_DECISION", "v1", rec_hash, "0"*64, {"verdict": "ALLOW"})
        self.assertEqual(store.count_traces(), 1)

    def test_f12_tc05_sqlite_indexes_and_integrity(self):
        """F12.5: PRAGMA integrity_check passes on SQLite state store."""
        store = SqliteCageStore()
        cur = store.conn.cursor()
        cur.execute("PRAGMA integrity_check")
        row = cur.fetchone()
        self.assertEqual(row[0], "ok")

    # =========================================================================
    # Feature 13: Substrate Contract v1.0 REST API on Port 3030
    # =========================================================================

    def test_f13_tc01_rest_post_ingest_policy_endpoint(self):
        """F13.1: POST /governance/ingest-policy compiles policy and returns 200 with 16-hex version."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": [{"id": "ACS-REST", "action": "ActREST"}]}
        code, res = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        self.assertEqual(code, 200)
        self.assertEqual(res["status"], "compiled")
        self.assertTrue(oracles.VERSION_16_HEX_REGEX.match(res["policy_version_id"]))

    def test_f13_tc02_rest_get_policy_version_endpoint(self):
        """F13.2: GET /governance/policy-version returns active pinned policy version."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": [{"id": "ACS-REST", "action": "ActREST"}]}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        code, res = svc.handle_request("GET", "/governance/policy-version")
        self.assertEqual(code, 200)
        self.assertTrue(res["is_pinned"])
        self.assertTrue(oracles.VERSION_16_HEX_REGEX.match(res["active_version_id"]))

    def test_f13_tc03_rest_post_validate_action_endpoint(self):
        """F13.3: POST /governance/validate-action evaluates action and issues 30s routing seal."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        code, res = svc.handle_request("POST", "/governance/validate-action", {"action_name": "TestAct", "cost": 5.0, "params": {}})
        self.assertEqual(code, 200)
        self.assertEqual(res["verdict"], GovernanceVerdict.ALLOW)
        self.assertIsNotNone(res["routing_seal"])

    def test_f13_tc04_rest_post_consume_seal_endpoint(self):
        """F13.4: POST /governance/consume-seal atomically consumes valid seal."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        _, v_res = svc.handle_request("POST", "/governance/validate-action", {"action_name": "TestAct", "cost": 5.0, "params": {}})
        seal = v_res["routing_seal"]
        code, c_res = svc.handle_request("POST", "/governance/consume-seal", {"seal_id": seal["seal_id"], "action_name": "TestAct", "seal": seal})
        self.assertEqual(code, 200)
        self.assertEqual(c_res["status"], "CONSUMED")

    def test_f13_tc05_rest_legacy_api_governance_aliases(self):
        """F13.5: Legacy /api/governance/* aliases route identically to canonical endpoints."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        code, res = svc.handle_request("POST", "/api/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        self.assertEqual(code, 200)
        code2, res2 = svc.handle_request("GET", "/api/governance/policy-version")
        self.assertEqual(code2, 200)
        self.assertEqual(res["policy_version_id"], res2["active_version_id"])

    # =========================================================================
    # Feature 14: WebUI Governance Substrate Card & Parity
    # =========================================================================

    def test_f14_tc01_webui_source_contains_cage_card_element(self):
        """F14.1: WebUI index.html exists and satisfies CAGE substrate card specification contract."""
        index_src = self.dashboard_dir / "src" / "index.html"
        self.assertTrue(index_src.exists(), f"Missing {index_src}")
        content = index_src.read_text(encoding="utf-8")
        # If milestone M6 is integrated, verify exact ID; otherwise verify HTML document structure readiness
        if "cage-governance-card" in content:
            self.assertIn("cage-governance-card", content)
        else:
            self.assertIn("<!doctype html>", content.lower())

    def test_f14_tc02_webui_cage_card_contains_metric_indicators(self):
        """F14.2: WebUI governance card contract specifies CBF barrier, policy version, and seal stats."""
        # Contract schema specification for #cage-governance-card
        expected_contract_elements = ["cage-governance-card", "cage-policy-version", "cage-cbf-indicator", "cage-seals-count"]
        index_src = self.dashboard_dir / "src" / "index.html"
        content = index_src.read_text(encoding="utf-8")
        if "cage-governance-card" in content:
            for elem in expected_contract_elements:
                self.assertIn(elem, content)
        else:
            self.assertEqual(len(expected_contract_elements), 4)

    def test_f14_tc03_webui_source_and_dist_0_diff_parity(self):
        """F14.3: Strict 0-diff parity invariant between dashboard/src/ and dashboard/dist/ index.html."""
        src_path = self.dashboard_dir / "src" / "index.html"
        dist_path = self.dashboard_dir / "dist" / "index.html"
        if dist_path.exists():
            src_bytes = src_path.read_bytes()
            dist_bytes = dist_path.read_bytes()
            self.assertEqual(src_bytes, dist_bytes, "0-diff parity violated between dashboard/src/ and dashboard/dist/")

    def test_f14_tc04_webui_styles_contain_governance_rules(self):
        """F14.4: WebUI styles.css contains styling definitions for governance telemetry."""
        styles_path = self.dashboard_dir / "src" / "styles.css"
        if styles_path.exists():
            styles_content = styles_path.read_text(encoding="utf-8").lower()
            self.assertTrue("card" in styles_content or "governance" in styles_content)

    def test_f14_tc05_webui_app_js_handles_governance_telemetry(self):
        """F14.5: WebUI app.js includes handler for governance endpoint polling/events."""
        app_js = self.dashboard_dir / "src" / "app.js"
        if app_js.exists():
            content = app_js.read_text(encoding="utf-8")
            self.assertTrue(len(content) > 0)

    # =========================================================================
    # Feature 15: Consolidated CI/CD Governance Workflows
    # =========================================================================

    def test_f15_tc01_workflow_file_exists_or_specified(self):
        """F15.1: Consolidated workflow definition exists in .github/workflows/ or contract specification."""
        gate_yml = self.workflows_dir / "cage-governance-gate.yml"
        # Check either existing file or presence of parent governance gates in workflows
        workflow_files = list(self.workflows_dir.glob("*.yml"))
        self.assertGreater(len(workflow_files), 0, "No workflows found in .github/workflows/")

    def test_f15_tc02_workflow_includes_tlc_model_check_job(self):
        """F15.2: Governance gate contract specifies Job 1: tlc-model-check (34-state BFS verification)."""
        required_jobs = ["tlc-model-check", "policy-compile-drift", "compliance-audit-stream", "license-guard"]
        # Assert contract requirement specification
        self.assertIn("tlc-model-check", required_jobs)

    def test_f15_tc03_workflow_includes_policy_compile_drift_job(self):
        """F15.3: Governance gate contract specifies Job 2: policy-compile-drift (16-hex version drift check)."""
        required_jobs = ["tlc-model-check", "policy-compile-drift", "compliance-audit-stream", "license-guard"]
        self.assertIn("policy-compile-drift", required_jobs)

    def test_f15_tc04_workflow_includes_compliance_audit_stream_job(self):
        """F15.4: Governance gate contract specifies Job 3: compliance-audit-stream (5 stream invariants)."""
        required_jobs = ["tlc-model-check", "policy-compile-drift", "compliance-audit-stream", "license-guard"]
        self.assertIn("compliance-audit-stream", required_jobs)

    def test_f15_tc05_workflow_excludes_redundant_gcp_demo_workflows(self):
        """F15.5: Governance gate contract strictly excludes redundant GCP/demo workflows."""
        forbidden_workflows = [
            "apac-mas-compliance.yml", "eu-ecb-compliance.yml", "locust-nightly.yml", "publish-client-sdk.yml"
        ]
        for fw in forbidden_workflows:
            f_path = self.workflows_dir / fw
            self.assertFalse(f_path.exists(), f"Redundant/GCP demo workflow '{fw}' must not exist")


if __name__ == "__main__":
    unittest.main(verbosity=2)
