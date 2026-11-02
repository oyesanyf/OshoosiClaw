"""
Tier 4: Real-World Scenarios Test Suite for CAGE Governance Substrate.
Simulates production agent workflows, continuous cybernetic feedback loops,
adversarial attack mitigations, and operational daemon lifecycles across R1-R8.
8 comprehensive real-world scenarios from TEST_INFRA.md.
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


class TestTier4RealWorldScenarios(unittest.TestCase):
    """Tier 4: End-to-End Real-World Application Workloads."""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.dashboard_dir = cls.root / "dashboard"

    # =========================================================================
    # Scenario 1: Multi-Format Policy Ingestion Pipeline
    # =========================================================================
    def test_scenario_01_multi_format_ingestion_pipeline(self):
        """Scenario 1: Ingest ACS policy, pin version, detect conflict on duplicate mismatch, verify 409."""
        svc = oracles.CageRestService()

        # Step 1: Client submits ACS policy
        acs_policy = {
            "name": "SecOpsExecutionPolicy",
            "version": "1.0.0",
            "behaviorDeclarations": [
                {
                    "id": "ACS-SECOPS-001",
                    "action": "ExecuteRemediationScript",
                    "hazardRefs": ["H-SECOPS-01"],
                    "constraints": [{"parameter": "timeout_seconds", "type": "greater_than", "value": 60.0}]
                }
            ]
        }
        code, res = svc.handle_request("POST", "/governance/ingest-policy", {
            "policy_content": json.dumps(acs_policy),
            "pin_version": True
        })
        self.assertEqual(code, 200)
        self.assertEqual(res["format_detected"], PolicyFormat.ACS)
        pinned_version = res["policy_version_id"]
        self.assertTrue(oracles.VERSION_16_HEX_REGEX.match(pinned_version))

        # Step 2: Query active pinned version
        q_code, q_res = svc.handle_request("GET", "/governance/policy-version")
        self.assertEqual(q_code, 200)
        self.assertEqual(q_res["active_version_id"], pinned_version)

        # Step 3: Adversary or drifted CI pipeline attempts to ingest altered policy
        drifted_policy = copy.deepcopy(acs_policy)
        drifted_policy["behaviorDeclarations"][0]["constraints"][0]["value"] = 300.0
        drift_code, drift_res = svc.handle_request("POST", "/governance/ingest-policy", {
            "policy_content": json.dumps(drifted_policy),
            "pin_version": True
        })
        self.assertEqual(drift_code, 409)
        self.assertEqual(drift_res["error"], "POLICY_VERSION_MISMATCH")
        self.assertEqual(drift_res["pinned_version"], pinned_version)

    # =========================================================================
    # Scenario 2: Autonomous Financial Agent Loop with CBF Fuel
    # =========================================================================
    def test_scenario_02_autonomous_financial_agent_loop(self):
        """Scenario 2: Phase 1 risk check, Phase 2 CBF fuel budget consumption, seal issuance, execution, audit."""
        svc = oracles.CageRestService()
        policy = {
            "behaviorDeclarations": [
                {"id": "ACS-FIN-LOOP", "action": "RebalancePortfolio"}
            ]
        }
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(policy), "pin_version": True})

        # Step 1: Agent requests 5 successive rebalance operations with cost 10 each (Initial budget=100, b_min=10)
        leaf_hashes = []
        for step in range(5):
            val_code, val_res = svc.handle_request("POST", "/governance/validate-action", {
                "action_name": "RebalancePortfolio",
                "cost": 10.0,
                "params": {"step": step}
            })
            self.assertEqual(val_code, 200)
            self.assertEqual(val_res["verdict"], GovernanceVerdict.ALLOW)
            seal = val_res["routing_seal"]
            self.assertIsNotNone(seal)

            # Step 2: Actuator consumes seal
            cons_code, cons_res = svc.handle_request("POST", "/governance/consume-seal", {
                "seal_id": seal["seal_id"],
                "action_name": "RebalancePortfolio",
                "params": {"step": step},
                "seal": seal
            })
            self.assertEqual(cons_code, 200)
            self.assertEqual(cons_res["status"], "CONSUMED")

            rec_hash = hashlib.sha256(f"financial_step_{step}:{seal['seal_id']}".encode()).hexdigest().lower()
            leaf_hashes.append(rec_hash)

        # Step 3: Compute Merkle root of the loop execution
        merkle_root = MerkleAuditTree.compute_root(leaf_hashes)
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(merkle_root))
        # Final budget should be 100 - (5 * 10) = 50.0
        self.assertEqual(svc.cbf.budget, 50.0)

    # =========================================================================
    # Scenario 3: Actuation Refusal & Fiscal Rollback
    # =========================================================================
    def test_scenario_03_actuation_refusal_and_fiscal_rollback(self):
        """Scenario 3: Injected unsafe parameters trigger CBF denial, assert zero leakage and 64-hex refusal receipt."""
        svc = oracles.CageRestService()
        policy = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(policy), "pin_version": True})
        initial_budget = svc.cbf.budget  # 100.0

        # Attempt massive allocation (cost 95 exceeds safety margin where b_min=10)
        code, res = svc.handle_request("POST", "/governance/validate-action", {
            "action_name": "OverdraftActuation",
            "cost": 95.0,
            "params": {"target": "cluster_scale"}
        })
        self.assertEqual(code, 200)
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)
        self.assertIsNone(res["routing_seal"])

        # Check zero fiscal leakage invariant
        self.assertEqual(svc.cbf.budget, initial_budget)

        # Check 64-hex refusal receipt
        proof_hash = res["proof_hash"]
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(proof_hash))

    # =========================================================================
    # Scenario 4: Replay & Seal Expiration Attack Defense
    # =========================================================================
    def test_scenario_04_replay_and_seal_expiration_attack_defense(self):
        """Scenario 4: Attempt actuation with expired seal (>30s) or replayed seal, assert fail-closed rejection."""
        gate = HostCapabilityGate()
        now = 1700000000
        seal = issue_routing_seal("DeployCode", {"sha": "abc"}, "v1_sec", issued_at=now)

        # 1. Authentic execution at t = now + 10s succeeds
        res1 = gate.validate_and_consume(seal, "DeployCode", {"sha": "abc"}, current_time_utc=now + 10)
        self.assertEqual(res1["status"], "CONSUMED")

        # 2. Replay attack with same seal at t = now + 15s blocked
        with self.assertRaises(SealRejectionError) as ctx_replay:
            gate.validate_and_consume(seal, "DeployCode", {"sha": "abc"}, current_time_utc=now + 15)
        self.assertIn("Replay detected", str(ctx_replay.exception))

        # 3. New seal presented at t = now + 35s (expired TTL) blocked
        seal_expired = issue_routing_seal("DeployCode", {"sha": "abc"}, "v1_sec", issued_at=now)
        with self.assertRaises(SealRejectionError) as ctx_exp:
            gate.validate_and_consume(seal_expired, "DeployCode", {"sha": "abc"}, current_time_utc=now + 35)
        self.assertIn("expired", str(ctx_exp.exception).lower())

    # =========================================================================
    # Scenario 5: Formal Model Space Verification (34 vs 17 States)
    # =========================================================================
    def test_scenario_05_formal_model_space_verification(self):
        """Scenario 5: Execute 34-state BFS engine, assert 34 gated states vs 17 ungated counterexample states."""
        # Explore gated state space
        gated_states, gated_violations = FormalBfsModelEngine.explore_gated_model()
        self.assertEqual(len(gated_states), 34)
        self.assertEqual(len(gated_violations), 0)

        # Explore ungated state space (counterexample)
        ungated_states, ungated_violations = FormalBfsModelEngine.explore_ungated_counterexample()
        self.assertEqual(len(ungated_states), 17)
        self.assertGreater(len(ungated_violations), 0)

        # Formal separation check
        self.assertNotEqual(gated_states, ungated_states)
        self.assertEqual(len(gated_states) - len(ungated_states), 17)

    # =========================================================================
    # Scenario 6: End-to-End REST Governance Daemon Lifecycle
    # =========================================================================
    def test_scenario_06_e2e_rest_governance_daemon_lifecycle(self):
        """Scenario 6: POST ingest-policy -> GET policy-version -> POST validate-action -> POST consume-seal -> GET trace/verify."""
        svc = oracles.CageRestService()

        # Step 1: Ingest Policy
        pol = {
            "stpa_control_structure": {
                "unsafe_control_actions": []
            }
        }
        c1, r1 = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(pol), "pin_version": True})
        self.assertEqual(c1, 200)
        v_id = r1["policy_version_id"]

        # Step 2: Policy Version Query
        c2, r2 = svc.handle_request("GET", "/governance/policy-version")
        self.assertEqual(c2, 200)
        self.assertEqual(r2["active_version_id"], v_id)

        # Step 3: Validate Action
        c3, r3 = svc.handle_request("POST", "/governance/validate-action", {
            "expected_policy_version": v_id,
            "action_name": "LifecycleAction",
            "cost": 5.0,
            "params": {"target": "sandbox"}
        })
        self.assertEqual(c3, 200)
        self.assertEqual(r3["verdict"], GovernanceVerdict.ALLOW)
        seal = r3["routing_seal"]

        # Step 4: Consume Seal
        c4, r4 = svc.handle_request("POST", "/governance/consume-seal", {
            "seal_id": seal["seal_id"],
            "action_name": "LifecycleAction",
            "params": {"target": "sandbox"},
            "seal": seal
        })
        self.assertEqual(c4, 200)
        self.assertEqual(r4["status"], "CONSUMED")

        # Step 5: Verify Trace Stream
        c5, r5 = svc.handle_request("GET", "/governance/trace/verify")
        self.assertEqual(c5, 200)
        self.assertEqual(r5["status"], "CONFORMANT")
        self.assertEqual(r5["findings_count"], 0)

    # =========================================================================
    # Scenario 7: WebUI Live Observability & 0-Diff Parity
    # =========================================================================
    def test_scenario_07_webui_live_observability_and_parity(self):
        """Scenario 7: Assert 0-diff byte-for-byte parity across dashboard/src/ and dashboard/dist/."""
        src_dir = self.dashboard_dir / "src"
        dist_dir = self.dashboard_dir / "dist"
        self.assertTrue(src_dir.exists())
        self.assertTrue(dist_dir.exists())

        # Compare matching files between src and dist
        src_files = list(src_dir.rglob("*"))
        compared_count = 0
        for s_file in src_files:
            if s_file.is_file():
                rel_path = s_file.relative_to(src_dir)
                d_file = dist_dir / rel_path
                if d_file.exists():
                    self.assertEqual(
                        s_file.read_bytes(),
                        d_file.read_bytes(),
                        f"0-diff parity failure on {rel_path}"
                    )
                    compared_count += 1

        self.assertGreater(compared_count, 0, "No files compared between dashboard/src and dashboard/dist")

    # =========================================================================
    # Scenario 8: Multi-Arm Lateral Containment with CAGE Gate
    # =========================================================================
    def test_scenario_08_multi_arm_lateral_containment_with_cage_gate(self):
        """Scenario 8: High-risk tool invocation blocked without active seal, passes with valid seal."""
        gate = HostCapabilityGate()
        action_name = "AccountingLedgerWrite"
        params = {"amount": 100000, "beneficiary": "vendor"}

        # Attempt 1: Direct unmediated bind without seal fails closed (NoDirectBind)
        with self.assertRaises(SealRejectionError):
            gate.validate_and_consume({}, action_name, params)

        # Attempt 2: Mediated actuation via valid CAGE governance clearance succeeds
        seal = issue_routing_seal(action_name, params, "v_arm_contained")
        outcome = gate.validate_and_consume(seal, action_name, params)
        self.assertEqual(outcome["status"], "CONSUMED")
        self.assertEqual(outcome["action_name"], action_name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
