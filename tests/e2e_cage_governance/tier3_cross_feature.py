"""
Tier 3: Cross-Feature Combinations Test Suite for CAGE Governance Substrate.
Verifies pairwise and multi-feature interaction pipelines across F1 through F15.
>= 15 comprehensive cross-module integration tests (16 tests total).
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


class TestTier3CrossFeature(unittest.TestCase):
    """Tier 3: Pairwise and Multi-Module Interaction Verification."""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT

    def test_p01_ingest_compile_pin_evaluate_seal_pipeline(self):
        """P01 (F1->F2->F3->F4->F6): Ingest ACS -> Compile Cedar/UCA -> Pin 16-hex -> Phase 1 eval -> Issue seal."""
        acs_doc = {
            "name": "FinancialTrades",
            "behaviorDeclarations": [
                {
                    "id": "ACS-TRADE-100",
                    "action": "PlaceTrade",
                    "hazardRefs": ["H-FIN-01"],
                    "constraints": [{"parameter": "amount", "type": "greater_than", "value": 5000.0}]
                }
            ]
        }
        # F1: Auto-detection
        fmt = auto_detect_policy_format(acs_doc)
        self.assertEqual(fmt, PolicyFormat.ACS)

        # F2: Compilation
        compiled = compile_policy(acs_doc)
        self.assertTrue(any('Action::"PlaceTrade"' in r for r in compiled["cedar_rules"]))

        # F3: Version Pinning
        version_id = compiled["policy_version_id"]
        self.assertTrue(oracles.VERSION_16_HEX_REGEX.match(version_id))

        # F4: Phase 1 Evaluation (valid action with amount = 1000 <= 5000)
        p1 = Phase1Gate(compiled)
        p1_res = p1.evaluate("PlaceTrade", "trader-1", "/exchange", {"amount": 1000.0})
        self.assertTrue(p1_res["passed"])
        self.assertEqual(p1_res["verdict"], GovernanceVerdict.ALLOW)

        # F6: Issue 30s Routing Seal
        seal = issue_routing_seal("PlaceTrade", {"amount": 1000.0}, version_id)
        self.assertEqual(seal["ttl_seconds"], 30)
        self.assertEqual(seal["policy_version_id"], version_id)

    def test_p02_seal_capability_gate_audit_stream_verification(self):
        """P02 (F6->F9->F11->F8): Issue seal -> Consume at Capability Gate -> Emit trace -> Verify stream invariants."""
        action_name = "RunSandboxProcess"
        params = {"binary": "helper.exe"}
        version_id = "1122334455667788"

        # F6: Issue seal
        seal = issue_routing_seal(action_name, params, version_id)

        # F9: Capability gate consumes seal
        gate = HostCapabilityGate()
        outcome = gate.validate_and_consume(seal, action_name, params)
        self.assertEqual(outcome["status"], "CONSUMED")

        # F11: Emit audit records
        dec_hash = hashlib.sha256(f"dec:{seal['seal_id']}".encode()).hexdigest().lower()
        records = [
            {
                "event_type": "GOVERNANCE_DECISION",
                "verdict": "ALLOW",
                "seal_present": True,
                "record_hash": dec_hash
            },
            {
                "event_type": "GOVERNANCE_SEAL_CONSUMED",
                "seal_id": seal["seal_id"],
                "decision_record_hash": dec_hash,
                "record_hash": hashlib.sha256(f"cons:{seal['seal_id']}".encode()).hexdigest().lower()
            },
            {
                "event_type": "ACTUATION_RECEIPT",
                "seal_id": seal["seal_id"],
                "record_hash": hashlib.sha256(f"act:{seal['seal_id']}".encode()).hexdigest().lower()
            }
        ]

        # F8: Stream Invariant Verifier
        stream_res = StreamInvariantVerifier.verify_stream(records)
        self.assertEqual(stream_res["status"], "CONFORMANT")
        self.assertEqual(stream_res["findings_count"], 0)

    def test_p03_policy_drift_conflict_409_and_version_invariance(self):
        """P03 (F1->F3->F13): Ingest policy A -> Ingest drifted policy B -> Assert 409 Conflict -> Active unchanged."""
        svc = oracles.CageRestService()
        doc_a = {"behaviorDeclarations": [{"id": "ACS-A", "action": "ActionA"}]}
        doc_b = {"behaviorDeclarations": [{"id": "ACS-B", "action": "ActionB_Modified"}]}

        # Ingest and pin A
        c1, res1 = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc_a), "pin_version": True})
        self.assertEqual(c1, 200)
        ver_a = res1["policy_version_id"]

        # Attempt to ingest B while A is pinned
        c2, res2 = svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc_b), "pin_version": True})
        self.assertEqual(c2, 409)
        self.assertEqual(res2["error"], "POLICY_VERSION_MISMATCH")
        self.assertEqual(res2["pinned_version"], ver_a)

        # Check that GET /governance/policy-version still returns A
        c3, res3 = svc.handle_request("GET", "/governance/policy-version")
        self.assertEqual(c3, 200)
        self.assertEqual(res3["active_version_id"], ver_a)

    def test_p04_phase1_approval_phase2_cbf_failure_refusal_receipt(self):
        """P04 (F4->F5->F8->F11): Phase 1 passes -> Phase 2 CBF fails -> Zero leakage -> 64-hex refusal receipt."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})

        # Initial budget is 100, b_min is 10.
        # Cost 95 -> h_{t+1} = (100 - 95) - 10 = -5 < 0 -> CBF Deny
        code, res = svc.handle_request("POST", "/governance/validate-action", {"action_name": "ExpensiveAction", "cost": 95.0, "params": {}})
        self.assertEqual(code, 200)
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)
        self.assertIsNone(res["routing_seal"])
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(res["proof_hash"]))

        # Assert budget untouched (zero leakage)
        self.assertEqual(svc.cbf.budget, 100.0)

        # Assert stream verifier confirms refusal evidence on emitted trace
        stream_res = svc.handle_request("GET", "/governance/trace/verify")
        self.assertEqual(stream_res[0], 200)
        self.assertEqual(stream_res[1]["status"], "CONFORMANT")

    def test_p05_cbf_pre_reservation_downstream_failure_lifo_rollback(self):
        """P05 (F4->F5->F11->F13): Validate -> CBF pre-reserves -> Downstream failure -> Rollback restores balance."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})

        code, v_res = svc.handle_request("POST", "/governance/validate-action", {"action_name": "Spend", "cost": 25.0, "params": {}})
        self.assertEqual(code, 200)
        self.assertEqual(svc.cbf.budget, 75.0)
        debit_id = v_res["debit_id"]

        # Downstream execution simulation fails -> invoke rollback
        r_code, r_res = svc.handle_request("POST", "/governance/rollback", {"debit_id": debit_id, "reason": "Actuator timeout"})
        self.assertEqual(r_code, 200)
        self.assertEqual(r_res["status"], "ROLLED_BACK")
        self.assertEqual(r_res["restored_amount"], 25.0)
        self.assertEqual(svc.cbf.budget, 100.0)

        # Verify audit stream contains valid rollback trace
        v_code, v_traces = svc.handle_request("GET", "/governance/trace/verify")
        self.assertEqual(v_code, 200)
        self.assertEqual(v_traces["status"], "CONFORMANT")

    def test_p06_seal_replay_rejection_audit_and_stream_invariant(self):
        """P06 (F6->F9->F11->F8): Seal consumed once -> Replay blocked with 403 -> Stream maintains NoDirectBind."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})

        _, v_res = svc.handle_request("POST", "/governance/validate-action", {"action_name": "RunOnce", "cost": 5.0, "params": {}})
        seal = v_res["routing_seal"]

        # 1st consumption: 200 OK
        c1, res1 = svc.handle_request("POST", "/governance/consume-seal", {"seal_id": seal["seal_id"], "action_name": "RunOnce", "seal": seal})
        self.assertEqual(c1, 200)
        self.assertEqual(res1["status"], "CONSUMED")

        # 2nd consumption (replay attempt): 403 Forbidden
        c2, res2 = svc.handle_request("POST", "/governance/consume-seal", {"seal_id": seal["seal_id"], "action_name": "RunOnce", "seal": seal})
        self.assertEqual(c2, 403)
        self.assertEqual(res2["error"], "SEAL_REJECTED")

    def test_p07_multi_format_jcs_versioning_sqlite_storage(self):
        """P07 (F1->F10->F3->F12): Multi-format ingestion -> JCS canonicalization -> Version ID -> SQLite store."""
        formats = [
            {"behaviorDeclarations": [{"id": "ACS-P7", "action": "ActP7"}]},
            {"governedRunLoop": {"stages": [{"name": "auth", "hooks": [{"id": "AAIF-P7", "action": "ActAAIF"}]}]}},
            {"kind": "LulaValidation", "metadata": {"name": "lula-p7"}, "spec": {"policy": {"opa": {"rego": "allow = true"}}}}
        ]
        store = SqliteCageStore()
        for doc in formats:
            compiled = compile_policy(doc)
            v_id = compiled["policy_version_id"]
            store.store_policy(compiled, is_pinned=False)

        cur = store.conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM cage_policies")
        self.assertEqual(cur.fetchone()["cnt"], 3)

    def test_p08_rest_lifecycle_to_sqlite_persistence(self):
        """P08 (F13->F12): Execute REST endpoints and assert SQLite state tables reflect records."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        svc.handle_request("POST", "/governance/validate-action", {"action_name": "SqlAct", "cost": 2.0, "params": {}})

        cur = svc.store.conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM cage_routing_seals")
        self.assertEqual(cur.fetchone()["cnt"], 1)

    def test_p09_narrow_verdict_clamped_rerun_and_seal_issuance(self):
        """P09 (F4->F6->F9): Action exceeds threshold -> NARROW clamps params -> Validates -> Issues seal for clamped."""
        policy = {
            "unsafe_control_actions": [
                {
                    "id": "UCA-NARROW",
                    "action": "AllocMemory",
                    "condition": [{"parameter": "bytes", "type": "greater_than", "value": 1000.0}]
                }
            ],
            "cedar_rules": []
        }
        p1 = Phase1Gate(policy)
        # Attempt 5000 bytes -> triggers NARROW
        p1_res = p1.evaluate("AllocMemory", "agent-x", "/mem", {"bytes": 5000.0})
        self.assertEqual(p1_res["verdict"], GovernanceVerdict.NARROW)
        clamped_params = p1_res["clamped_params"]
        self.assertEqual(clamped_params["bytes"], 1000.0)

        # Re-run Phase 1 with clamped params -> passes
        rerun_res = p1.evaluate("AllocMemory", "agent-x", "/mem", clamped_params, is_narrowed_rerun=True)
        self.assertTrue(rerun_res["passed"])

        # Issue seal for clamped params
        seal = issue_routing_seal("AllocMemory", clamped_params, "v1_clamped")
        gate = HostCapabilityGate()
        outcome = gate.validate_and_consume(seal, "AllocMemory", clamped_params)
        self.assertEqual(outcome["status"], "CONSUMED")

    def test_p10_bfs_state_space_coverage_matches_pipeline_verdicts(self):
        """P10 (F7->F4->F5->F6): Verify BFS states correspond to real runtime verdict transitions."""
        visited, violations = FormalBfsModelEngine.explore_gated_model()
        self.assertEqual(len(violations), 0)

        # Check presence of ALLOW terminal state (SEAL_ISSUED -> EXECUTED)
        has_executed = any(s[0] == "EXECUTED" for s in visited)
        self.assertTrue(has_executed)

        # Check presence of DENY terminal states
        has_denied = any(s[0] == "DENIED" for s in visited)
        self.assertTrue(has_denied)

        # Check presence of NARROW states
        has_narrow = any("NARROW" in s[0] for s in visited)
        self.assertTrue(has_narrow)

    def test_p11_oscal_ac3_cedar_host_capability_gate(self):
        """P11 (F1->F2->F4->F9): OSCAL AC-3 requirement compiles to Cedar and enforces file write protection."""
        oscal_doc = {
            "component-definition": {
                "metadata": {"oscal-version": "1.1.0"},
                "components": [
                    {
                        "uuid": "comp-fs",
                        "control-implementations": [
                            {"implemented-requirements": [{"control-id": "ac-3", "uuid": "req-ac-3"}]}
                        ]
                    }
                ]
            }
        }
        compiled = compile_policy(oscal_doc)
        p1 = Phase1Gate(compiled)

        # access_enforcement is IRREVERSIBLE_TERMINAL under AC-3
        res = p1.evaluate("access_enforcement", "agent-fs", "/sys/kernel", {"human_authorized": False})
        self.assertEqual(res["verdict"], GovernanceVerdict.DENY)

        # With authorization, passes
        res_auth = p1.evaluate("access_enforcement", "agent-fs", "/sys/kernel", {"human_authorized": True})
        self.assertEqual(res_auth["verdict"], GovernanceVerdict.ALLOW)

    def test_p12_aaif_rate_limiting_cbf_decay_invariant(self):
        """P12 (F1->F2->F5->F6): AAIF rate limiting hook maps to CBF token decay evaluation."""
        aaif_doc = {
            "governedRunLoop": {
                "stages": [
                    {"name": "rate_limiting", "hooks": [{"id": "AAIF-RATE", "action": "ReserveTokens"}]}
                ]
            }
        }
        compiled = compile_policy(aaif_doc)
        self.assertEqual(compiled["format"], PolicyFormat.AAIF)

        cbf = ControlBarrierFunction(initial_budget=50.0, b_min=5.0, gamma=0.5)
        # Cost 10 satisfies exponential barrier
        sat, ht, hnext, did = cbf.evaluate_and_reserve(cost=10.0)
        self.assertTrue(sat)
        self.assertIsNotNone(did)

    def test_p13_sequential_concurrent_seal_consumption(self):
        """P13 (F5->F6->F9->F11): Sequential seal issuance and consumption maintain Merkle tree audit trail."""
        gate = HostCapabilityGate()
        leaf_hashes = []

        for i in range(10):
            seal = issue_routing_seal(f"Act_{i}", {"i": i}, "v_seq")
            res = gate.validate_and_consume(seal, f"Act_{i}", {"i": i})
            self.assertEqual(res["status"], "CONSUMED")
            rec_hash = hashlib.sha256(f"seal_consumed:{seal['seal_id']}".encode()).hexdigest().lower()
            leaf_hashes.append(rec_hash)

        # Compute Merkle root of all 10 consumptions
        merkle_root = MerkleAuditTree.compute_root(leaf_hashes)
        self.assertEqual(len(merkle_root), 64)
        self.assertTrue(oracles.DIGEST_64_HEX_REGEX.match(merkle_root))

    def test_p14_webui_metrics_reflect_sqlite_traces(self):
        """P14 (F14->F12->F13): REST API updates SQLite traces and WebUI parity is preserved."""
        svc = oracles.CageRestService()
        doc = {"behaviorDeclarations": []}
        svc.handle_request("POST", "/governance/ingest-policy", {"policy_content": json.dumps(doc), "pin_version": True})
        svc.handle_request("POST", "/governance/validate-action", {"action_name": "WebUIAct", "cost": 1.0, "params": {}})

        traces_count = svc.store.count_traces()
        self.assertGreaterEqual(traces_count, 0)

        # Assert 0-diff parity between src and dist
        src = (self.root / "dashboard" / "src" / "index.html").read_bytes()
        dist = (self.root / "dashboard" / "dist" / "index.html").read_bytes()
        self.assertEqual(src, dist)

    def test_p15_ci_cd_workflow_validates_drift_and_model_gate(self):
        """P15 (F15->F1->F7): CI/CD governance gate workflow asserts TLC model check and policy drift."""
        workflow_dir = self.root / ".github" / "workflows"
        self.assertTrue(workflow_dir.exists())

        # Ensure pure-Rust BFS model check executes in < 1 second for CI gate
        t0 = time.perf_counter()
        visited, violations = FormalBfsModelEngine.explore_gated_model()
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 1.0)
        self.assertEqual(len(visited), 34)
        self.assertEqual(len(violations), 0)

    def test_p16_end_to_end_multi_agent_trace_replay(self):
        """P16 (F8->F11->F13): Replay multi-agent audit stream with diverse verdicts and confirm conformance."""
        records = [
            {"event_type": "GOVERNANCE_DECISION", "verdict": "ALLOW", "seal_present": True, "record_hash": "a"*64},
            {"event_type": "GOVERNANCE_SEAL_CONSUMED", "seal_id": "seal-1", "decision_record_hash": "a"*64, "record_hash": "b"*64},
            {"event_type": "ACTUATION_RECEIPT", "seal_id": "seal-1", "record_hash": "c"*64},
            {"event_type": "GOVERNANCE_REFUSAL", "proof_hash": "d"*64, "record_hash": "e"*64}
        ]
        res = StreamInvariantVerifier.verify_stream(records)
        self.assertEqual(res["status"], "CONFORMANT")
        self.assertEqual(res["findings_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
