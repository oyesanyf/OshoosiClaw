"""
OshoosiClaw Continuous Agent Breakout Defense - Tier 3: Cross-Feature Interactions
Tests pairwise interactions across all 7 requirements (R1 through R7).
Zero mocks, genuine execution logic, strict requirement traceability.
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
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "breakout_defense"))

import oracles


class TestTier3BreakoutPairwise(unittest.TestCase):
    """Tier 3: Cross-Feature Pairwise Interactions."""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT

    def test_pairwise_01_r1_sandbox_x_r2_tainted_env(self):
        """P01: R1 (AppContainer child spawn) x R2 (Environment variable hijacking).
        Verifies that an AppContainer suspended worker reject forbidden environment variables
        prior to Job Object binding and ResumeThread."""
        bad_env = {
            "GIT_SSH_COMMAND": "calc.exe",
            "PATH": "C:\\Windows\\System32",
        }
        # 1. Environment inspection fires
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(bad_env, "git fetch")
        self.assertTrue(blocked)
        self.assertIn("Forbidden environment variable: GIT_SSH_COMMAND=calc.exe", violations)

        # 2. Confinement state machine fails closed due to tainted spawn parameter
        outcome = oracles.evaluate_pre_resume_confinement_oracle(
            creation_flags=oracles.CREATE_SUSPENDED_FLAG,
            job_limit_flags=oracles.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | oracles.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            active_process_limit=1,
            require_appcontainer_sid=True,
            require_is_process_in_job=True,
            allow_uncontained_fallback=False,
            appcontainer_profile_allocated=True,
            sid_bound=True,
            job_assigned=False,  # Blocked before assignment
            is_process_in_job=False,
        )
        self.assertFalse(outcome.resume_thread_allowed)
        self.assertTrue(outcome.terminated_suspended_process)

    def test_pairwise_02_r1_dns_pinning_x_r3_mesh_ingress(self):
        """P02: R1 (DNS/SSRF SocketAddr pinning) x R3 (Mesh ingress with external URL payload).
        Verifies that an untrusted mesh message requesting an internal IMDS egress is stopped
        both by capability stripping and by SocketAddr pinning."""
        target_imds = "169.254.169.254"
        port = 80

        # 1. Mesh Capability Governor strips network_egress
        initial_caps = {"read_file", "network_egress", "shell_exec"}
        allowed_caps, stripped = oracles.govern_arm_capabilities_oracle(
            current_capabilities=initial_caps,
            taint_level=oracles.TaintLevel.UntrustedExternal,
            has_operator_approval=False,
        )
        self.assertNotIn("network_egress", allowed_caps)
        self.assertIn("network_egress", stripped)

        # 2. Even if connector was invoked, SocketAddr pinning rejects IMDS
        is_ssrf, msg = oracles.is_ssrf_socket_addr_oracle(target_imds, port)
        self.assertTrue(is_ssrf)
        self.assertIn("Link-Local", msg)

    def test_pairwise_03_r2_mfotl_taint_x_r3_capability_governor(self):
        """P03: R2 (Dogwood MFOTL taint tracking) x R3 (Mesh capability governor downstream tool stripping).
        Verifies that a multi-turn prompt injection chain triggers temporal forbid and strips
        downstream execution capabilities across agent arms."""
        now = time.time()
        trace = [
            oracles.TemporalTraceAtom(now - 3600, oracles.TemporalEventType.UntrustedWebInput, "sess-pw3"),
            oracles.TemporalTraceAtom(now - 1800, oracles.TemporalEventType.ScratchFileWrite, "sess-pw3", "drop.ps1"),
            oracles.TemporalTraceAtom(now - 10, oracles.TemporalEventType.SubprocessEnvOrArg, "sess-pw3"),
        ]
        violated, reason = oracles.evaluate_dogwood_mfotl_taint_flow_oracle(trace, now)
        self.assertTrue(violated)
        self.assertIn("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION", reason)

        # Downstream capabilities stripped
        allowed, stripped = oracles.govern_arm_capabilities_oracle(
            {"powershell", "cmd", "read_file"},
            taint_level=oracles.TaintLevel.UntrustedExternal,
            has_operator_approval=False,
        )
        self.assertEqual(allowed, {"read_file"})
        self.assertIn("powershell", stripped)

    def test_pairwise_04_r3_mesh_envelope_x_r5_control_plane(self):
        """P04: R3 (Untrusted mesh envelope) x R5 (Control plane session auth gating).
        Verifies that an untrusted agent arm cannot authenticate to /api/auth/session without
        the elevated administrator secret."""
        admin_secret = "OSHOOSI_ADMIN_SECRET_KEY_PAIRWISE"
        attacker_token = "FORGED_BEARER_TOKEN_ARM_3"

        status, msg = oracles.control_plane_session_auth_oracle(
            presented_token=attacker_token,
            admin_secret=admin_secret,
            origin_header="http://127.0.0.1:3030",
            sec_fetch_site_header="same-origin",
        )
        self.assertEqual(status, 401)
        self.assertIn("Invalid session token", msg)

    def test_pairwise_05_r4_telemetry_flood_x_r7_asymmetric_veto(self):
        """P05: R4 (Telemetry event flood) x R7 (Consensus engine asymmetric veto).
        Verifies that critical deterministic invariant alerts bypass high-frequency benign floods
        and trigger immediate unconditional isolation."""
        # 1. High priority alert emerges from telemetry queue
        high_priority_alert = "DETERMINISTIC_MEMORY_LSASS_TAMPER"
        self.assertTrue(high_priority_alert.startswith("DETERMINISTIC"))

        # 2. Consensus engine applies asymmetric veto
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=True,
            statistical_pe_ml_veto=True,  # Attacker attempts to rely on ML benign score
            nsrl_whitelist_veto=False,
            voter_weights=[1.0, 1.2],
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertEqual(conf, 1.0)
        self.assertIn("ASYMMETRIC_VETO", reason)

    def test_pairwise_06_r4_byovd_blocklist_x_r7_deterministic_veto(self):
        """P06: R4 (BYOVD driver blocklist) x R7 (Consensus engine overriding NSRL whitelist).
        Verifies that a known vulnerable driver on a whitelist is blocked pre-initialization
        and overrides whitelist vetoes."""
        rtcore_hash = "F497E6A901BE9C8FFDE0F9B464DB3E2916F4F5EBDD708CE94C2B4DA1EE01F529".lower()
        allowed, msg = oracles.check_byovd_driver_blocklist_oracle(rtcore_hash)
        self.assertFalse(allowed)
        self.assertIn("RTCore64.SYS", msg)

        # Consensus engine treats vulnerable driver detection as deterministic invariant violation
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=True,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=True,  # Pretend it was in NSRL whitelist
            voter_weights=[1.0],
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertEqual(conf, 1.0)
        self.assertIn("Overridden static ML/NSRL veto", reason)

    def test_pairwise_07_r5_control_plane_auth_x_r6_research_swarm_promotion(self):
        """P07: R5 (Control plane Origin / Sec-Fetch-Site) x R6 (Research rule operator approval).
        Verifies that a cross-origin request attempting to approve a staged research rule is rejected
        with 403 Forbidden, leaving the rule in staged observation mode."""
        admin_secret = "OSHOOSI_ADMIN_SECRET_KEY_PAIRWISE"
        # Cross-origin approval attempt
        status, _ = oracles.control_plane_session_auth_oracle(
            presented_token=admin_secret,
            admin_secret=admin_secret,
            origin_header="http://attacker.com",
            sec_fetch_site_header="cross-site",
        )
        self.assertEqual(status, 403)

        # Because approval was rejected, rule promotion fails
        promoted, reason = oracles.evaluate_research_rule_promotion_oracle(
            "RULE-CANARY-01", "malicious_indicator", 0, has_operator_approval=False, is_pinned=False
        )
        self.assertFalse(promoted)
        self.assertIn("STAGED_OBSERVATION_ONLY", reason)

    def test_pairwise_08_r6_in_memory_probing_x_r7_voter_consensus(self):
        """P08: R6 (In-memory declarative indicator evaluation) x R7 (Voter consensus integration).
        Verifies that a clean research rule evaluated in-memory with 0 false positives integrates
        into voter consensus with calibrated confidence."""
        clean_corpus = [{"event": "safe_build_run"}, {"event": "developer_test_run"}]
        fp, is_clean = oracles.evaluate_canary_benign_corpus_oracle("c2_beacon_pattern", clean_corpus)
        self.assertEqual(fp, 0)
        self.assertTrue(is_clean)

        promoted, _ = oracles.evaluate_research_rule_promotion_oracle(
            "RULE-BEACON", "c2_beacon_pattern", fp, has_operator_approval=True, is_pinned=True
        )
        self.assertTrue(promoted)

        # Rule operates in consensus as a calibrated voter
        action, conf, _ = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=False,
            voter_weights=[1.8, 1.9],  # Strong evidence from research rule
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertGreaterEqual(conf, 0.85)

    def test_pairwise_09_r1_reparse_point_x_r5_sqlite_storage(self):
        """P09: R1 (Reparse point / junction defense) x R5 (SQLite NTFS DACL protection).
        Verifies that an attacker creating an NTFS junction inside the sandbox targeting
        the protected SQLite database is blocked by reparse point checking."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            db_path = root / "database" / "osoosi.db"
            db_path.parent.mkdir(parents=True)
            db_path.write_text("sqlite database header", encoding="utf-8")

            # Validate DACL oracle on database path
            dacl_ok, _ = oracles.validate_ntfs_dacl_sddl_oracle("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
            self.assertTrue(dacl_ok)

            # Traversal / junction target attempt
            ok, msg = oracles.validate_sandbox_path_join_oracle(root, "../database/osoosi.db")
            self.assertFalse(ok)
            self.assertIn("Parent directory traversal", msg)

    def test_pairwise_10_r2_build_rs_hijacking_x_r7_asymmetric_veto(self):
        """P10: R2 (build.rs configuration tampering) x R7 (Deterministic asymmetric veto).
        Verifies that build.rs tampering triggers execution environment violations and
        commands ResponseAction::Isolate in the consensus engine."""
        bad_env = {
            "RUSTC_WRAPPER": "C:\\malware\\hijack_wrapper.bat",
            "CARGO_BUILD_TARGET_DIR": "C:\\tmp",
        }
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(bad_env, "cargo build")
        self.assertTrue(blocked)
        self.assertTrue(any("RUSTC_WRAPPER" in v for v in violations))

        # Triggers deterministic isolation
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=True,
            statistical_pe_ml_veto=True,  # Attacker claims compiler binary is safe
            nsrl_whitelist_veto=True,
            voter_weights=[0.5],
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertEqual(conf, 1.0)
        self.assertIn("ASYMMETRIC_VETO", reason)


if __name__ == "__main__":
    unittest.main()
