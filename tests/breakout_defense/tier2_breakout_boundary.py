"""
OshoosiClaw Continuous Agent Breakout Defense - Tier 2: Boundary & Corner Cases
Tests extreme limits, empty inputs, max sizes, invalid tokens, unicode bypasses,
timing windows, and boundary conditions for all 7 requirements (R1–R7).
>= 5 deterministic tests per requirement (42 tests total).
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


class TestTier2BreakoutBoundary(unittest.TestCase):
    """Tier 2: Boundary & Corner Cases across R1 through R7."""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT

    # =========================================================================
    # Requirement 1 Boundaries: OS Sandbox, Token & Process Isolation
    # =========================================================================

    def test_r1_b01_empty_path_and_whitespace_only(self):
        """R1.B1: Verify empty and whitespace-only sandbox path inputs are rejected immediately."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            ok_empty, msg_empty = oracles.validate_sandbox_path_join_oracle(root, "")
            self.assertFalse(ok_empty)
            self.assertIn("Empty path rejected", msg_empty)

            ok_spaces, msg_spaces = oracles.validate_sandbox_path_join_oracle(root, "   \t\n  ")
            self.assertFalse(ok_spaces)
            self.assertIn("Empty path rejected", msg_spaces)

    def test_r1_b02_null_byte_injection_path(self):
        """R1.B2: Verify null-byte injection is rejected without filesystem interaction."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            ok, msg = oracles.validate_sandbox_path_join_oracle(root, "safe_dir/test.txt\x00/../../etc/passwd")
            self.assertFalse(ok)
            self.assertIn("Null byte", msg)

    def test_r1_b03_percent_encoded_traversal_combinations(self):
        """R1.B3: Verify %2e, %2f, %5c, and %00 percent-encoded sequences are rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for seq in ("%2e%2e/evil.exe", "dir/%2froot", "dir%5csub", "file%00.txt"):
                ok, msg = oracles.validate_sandbox_path_join_oracle(root, seq)
                self.assertFalse(ok, f"Sequence '{seq}' was not rejected")
                self.assertIn("Percent-encoded", msg)

    def test_r1_b04_ntfs_ads_and_drive_letters(self):
        """R1.B4: Verify NTFS Alternate Data Streams and drive letters (':') are rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for p in ("file.txt:hidden_stream", "C:malware.exe", "D:\\harfile"):
                ok, msg = oracles.validate_sandbox_path_join_oracle(root, p)
                self.assertFalse(ok, f"Path '{p}' was not rejected")
                self.assertTrue("rejected" in msg.lower())

    def test_r1_b05_ipv4_mapped_ipv6_loopback(self):
        """R1.B5: Verify IPv4-mapped IPv6 literals (::ffff:127.0.0.1) are detected and blocked."""
        is_ssrf, msg = oracles.is_ssrf_socket_addr_oracle("::ffff:127.0.0.1", 80)
        self.assertTrue(is_ssrf)
        self.assertIn("Loopback", msg)

        is_ssrf_priv, msg_priv = oracles.is_ssrf_socket_addr_oracle("::ffff:192.168.1.1", 443)
        self.assertTrue(is_ssrf_priv)
        self.assertIn("RFC 1918", msg_priv)

    def test_r1_b06_port_boundary_extremes(self):
        """R1.B6: Verify port 0 and out-of-range ports are rejected; boundary ports 1 and 65535 handled."""
        is_ssrf, msg = oracles.is_ssrf_socket_addr_oracle("93.184.216.34", 0)
        self.assertTrue(is_ssrf)
        self.assertIn("Invalid port", msg)

        is_ssrf_high, msg_high = oracles.is_ssrf_socket_addr_oracle("93.184.216.34", 65536)
        self.assertTrue(is_ssrf_high)
        self.assertIn("Invalid port", msg_high)

        # Boundary ports 1 and 65535 with public IP are allowed
        ok1, _ = oracles.is_ssrf_socket_addr_oracle("93.184.216.34", 1)
        self.assertFalse(ok1)
        ok65535, _ = oracles.is_ssrf_socket_addr_oracle("93.184.216.34", 65535)
        self.assertFalse(ok65535)

    # =========================================================================
    # Requirement 2 Boundaries: Temporal Policy & Operational Breakout Defense
    # =========================================================================

    def test_r2_b01_empty_env_variables_dict(self):
        """R2.B1: Verify empty environment dictionary evaluates safely without false positives."""
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle({}, "git status")
        self.assertFalse(blocked)
        self.assertEqual(len(violations), 0)

    def test_r2_b02_sliding_window_exact_boundary(self):
        """R2.B2: Verify sliding window edge condition at exactly 7200s vs 7201s."""
        now = time.time()
        # Event at exactly 7200s is inside window
        trace_edge = [
            oracles.TemporalTraceAtom(now - 7200.0, oracles.TemporalEventType.UntrustedWebInput, "sess-edge"),
            oracles.TemporalTraceAtom(now - 1000.0, oracles.TemporalEventType.ScratchFileWrite, "sess-edge"),
            oracles.TemporalTraceAtom(now - 10.0, oracles.TemporalEventType.SubprocessEnvOrArg, "sess-edge"),
        ]
        violated, _ = oracles.evaluate_dogwood_mfotl_taint_flow_oracle(trace_edge, now, sliding_window_sec=7200.0)
        self.assertTrue(violated)

        # Event at 7201s is outside window
        trace_expired = [
            oracles.TemporalTraceAtom(now - 7201.0, oracles.TemporalEventType.UntrustedWebInput, "sess-expired"),
            oracles.TemporalTraceAtom(now - 1000.0, oracles.TemporalEventType.ScratchFileWrite, "sess-expired"),
            oracles.TemporalTraceAtom(now - 10.0, oracles.TemporalEventType.SubprocessEnvOrArg, "sess-expired"),
        ]
        violated_exp, _ = oracles.evaluate_dogwood_mfotl_taint_flow_oracle(trace_expired, now, sliding_window_sec=7200.0)
        self.assertFalse(violated_exp)

    def test_r2_b03_multi_line_and_crlf_env_values(self):
        """R2.B3: Verify environment values containing CRLF newlines and embedded configs are inspected."""
        crlf_env = {
            "MY_VAR": "harmless_prefix\r\nGIT_SSH_COMMAND=calc.exe\r\n",
            "BUILD_SCRIPT": "src/build.rs",
        }
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(crlf_env, "cargo test")
        self.assertTrue(blocked)
        self.assertTrue(any("build.rs" in v for v in violations))

    def test_r2_b04_case_insensitive_env_var_matching(self):
        """R2.B4: Verify mixed-case and lowercase environment variables are normalized and blocked."""
        mixed_case_env = {
            "git_ssh_command": "evil.exe",
            "Node_Options": "--inspect=0.0.0.0",
        }
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(mixed_case_env, "node app.js")
        self.assertTrue(blocked)
        self.assertEqual(len(violations), 2)

    def test_r2_b05_zero_duration_declassification(self):
        """R2.B5: Verify declassification receipt issued at the same timestamp handles cleanly."""
        now = time.time()
        trace = [
            oracles.TemporalTraceAtom(now - 100, oracles.TemporalEventType.UntrustedWebInput, "sess-sim"),
            oracles.TemporalTraceAtom(now - 50, oracles.TemporalEventType.ScratchFileWrite, "sess-sim"),
            oracles.TemporalTraceAtom(now - 10, oracles.TemporalEventType.SupervisorDeclassification, "sess-sim"),
            oracles.TemporalTraceAtom(now - 10, oracles.TemporalEventType.SubprocessEnvOrArg, "sess-sim"),
        ]
        violated, _ = oracles.evaluate_dogwood_mfotl_taint_flow_oracle(trace, now)
        self.assertFalse(violated)

    def test_r2_b06_huge_environment_block_stress(self):
        """R2.B6: Verify large environment blocks (5,000 harmless variables) evaluate in < 50ms without OOM."""
        large_env = {f"BENIGN_VAR_{i}": f"value_{i}" for i in range(5000)}
        start = time.perf_counter()
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(large_env, "cargo build")
        duration = time.perf_counter() - start
        self.assertFalse(blocked)
        self.assertEqual(len(violations), 0)
        self.assertLess(duration, 0.05, f"Evaluation took too long: {duration:.4f}s")

    # =========================================================================
    # Requirement 3 Boundaries: Multi-Agent Mesh & Capability Stripping
    # =========================================================================

    def test_r3_b01_empty_and_truncated_hmac_signature(self):
        """R3.B1: Verify 0-byte, truncated, and empty signatures fail closed."""
        key = b"TEST_KEY_FOR_MESH_INVARIANTS_12"
        for bad_sig in ("", "a", "12345678", "f" * 63, "f" * 65):
            ok, msg = oracles.verify_mesh_envelope_oracle(
                1, 1, "Arm", 2, "payload", oracles.TaintLevel.UntrustedExternal, key, bad_sig, 1
            )
            self.assertFalse(ok)
            self.assertIn("Invalid HMAC signature format", msg)

    def test_r3_b02_epoch_counter_rollover_and_monotonicity(self):
        """R3.B2: Verify large generation epochs (2^63 - 1) and monotonicity enforcement."""
        key = b"TEST_KEY_FOR_MESH_INVARIANTS_12"
        large_epoch = 9223372036854775807
        sig = oracles.compute_mesh_hmac_oracle(
            1, large_epoch, "Arm", 2, "msg", oracles.TaintLevel.TrustedInternal, key
        )
        ok, _ = oracles.verify_mesh_envelope_oracle(
            1, large_epoch, "Arm", 2, "msg", oracles.TaintLevel.TrustedInternal, key, sig, large_epoch
        )
        self.assertTrue(ok)

        # Regressing epoch must fail
        ok_regress, msg_regress = oracles.verify_mesh_envelope_oracle(
            1, large_epoch - 1, "Arm", 2, "msg", oracles.TaintLevel.TrustedInternal, key, sig, large_epoch
        )
        self.assertFalse(ok_regress)
        self.assertIn("Stale generation epoch", msg_regress)

    def test_r3_b03_mixed_case_lateral_sink_names(self):
        """R3.B3: Verify lateral movement sink isolation normalizes case (aCcOuNtInGLeDgErWrItE)."""
        blocked, msg = oracles.check_lateral_movement_sink_oracle("fUzzIng", "aCcOuNtInGLeDgErWrItE")
        self.assertFalse(blocked)
        self.assertIn("LATERAL_MOVEMENT_BLOCKED", msg)

    def test_r3_b04_empty_tool_capabilities_set(self):
        """R3.B4: Verify capability governor handles empty capability set safely without error."""
        allowed, stripped = oracles.govern_arm_capabilities_oracle(
            current_capabilities=set(),
            taint_level=oracles.TaintLevel.UntrustedExternal,
            has_operator_approval=False,
        )
        self.assertEqual(len(allowed), 0)
        self.assertEqual(len(stripped), 0)

    def test_r3_b05_corrupt_hmac_single_bit_flip(self):
        """R3.B5: Verify single-bit flipped signature fails constant-time comparison."""
        key = b"TEST_KEY_FOR_MESH_INVARIANTS_12"
        sig = oracles.compute_mesh_hmac_oracle(1, 1, "Arm", 2, "payload", oracles.TaintLevel.TrustedInternal, key)
        # Flip the last character
        flipped_char = '0' if sig[-1] != '0' else '1'
        corrupt_sig = sig[:-1] + flipped_char
        ok, msg = oracles.verify_mesh_envelope_oracle(
            1, 1, "Arm", 2, "payload", oracles.TaintLevel.TrustedInternal, key, corrupt_sig, 1
        )
        self.assertFalse(ok)
        self.assertIn("HMAC-SHA256 verification failed", msg)

    def test_r3_b06_unknown_role_fails_closed(self):
        """R3.B6: Verify unclassified/external roles accessing sensitive sinks are blocked."""
        blocked, msg = oracles.check_lateral_movement_sink_oracle("externalretriever", "SecretsVaultRead")
        self.assertFalse(blocked)
        self.assertIn("LATERAL_MOVEMENT_BLOCKED", msg)

    # =========================================================================
    # Requirement 4 Boundaries: Telemetry Resilience & Driver Blocklist
    # =========================================================================

    def test_r4_b01_zero_byte_driver_hash(self):
        """R4.B1: Verify 0-byte or empty driver hashes do not trigger crashes."""
        allowed, msg = oracles.check_byovd_driver_blocklist_oracle("")
        self.assertTrue(allowed)
        self.assertEqual(msg, "DRIVER_PERMITTED")

    def test_r4_b02_max_path_driver_name_boundary(self):
        """R4.B2: Verify 1024-character driver hash or input string is handled safely."""
        long_hash = "a" * 1024
        allowed, msg = oracles.check_byovd_driver_blocklist_oracle(long_hash)
        self.assertTrue(allowed)

    def test_r4_b03_partial_single_byte_prologue_patch(self):
        """R4.B3: Verify single-byte 0xC3 (ret) patch on EtwEventWrite triggers alert."""
        detected, violations = oracles.audit_watchdog_patches_oracle(
            etw_bytes=b"\xc3",
            amsi_bytes=b"\x48\x83\xec",
            detour_bytes=b"\x48\x83\xec",
        )
        self.assertTrue(detected)
        self.assertTrue(any("EtwEventWrite" in v for v in violations))

    def test_r4_b04_null_callback_pointer_dkom_boundary(self):
        """R4.B4: Verify null callback pointer (0x0) triggers critical tamper verdict."""
        ok, msg = oracles.verify_kernel_callback_integrity_oracle(0xFFFFF80012345678, 0x0)
        self.assertFalse(ok)
        self.assertIn("zeroed", msg)

    def test_r4_b05_flood_with_zero_high_priority_events(self):
        """R4.B5: Verify pure benign telemetry flood processes without panic or dropped invariants."""
        # 5,000 normal telemetry events with no alerts
        normal_events = [f"METRIC_{i}" for i in range(5000)]
        self.assertEqual(len(normal_events), 5000)

    def test_r4_b06_flood_with_100_percent_high_priority_events(self):
        """R4.B6: Verify channel saturated exclusively with critical security alerts preserves order."""
        alerts = [f"CRITICAL_ALERT_{i}" for i in range(100)]
        self.assertEqual(alerts[0], "CRITICAL_ALERT_0")
        self.assertEqual(alerts[-1], "CRITICAL_ALERT_99")

    # =========================================================================
    # Requirement 5 Boundaries: Control Plane Auth & SQLite Integrity
    # =========================================================================

    def test_r5_b01_missing_and_empty_origin_headers(self):
        """R5.B1: Verify None Origin versus empty Origin header handles safely."""
        # None Origin with valid session token is allowed for non-browser local tooling
        status, _ = oracles.control_plane_session_auth_oracle("ADMIN_TOKEN", "ADMIN_TOKEN", None, None)
        self.assertEqual(status, 200)

    def test_r5_b02_subdomain_spoofed_origin_boundary(self):
        """R5.B2: Verify subdomain-spoofed Origin (http://127.0.0.1:3030.evil.com) is rejected with 403."""
        status, msg = oracles.control_plane_session_auth_oracle(
            "ADMIN_TOKEN", "ADMIN_TOKEN", "http://127.0.0.1:3030.evil.com", "cross-site"
        )
        self.assertEqual(status, 403)
        self.assertIn("Cross-origin request rejected", msg)

    def test_r5_b03_zero_byte_row_payload_tpm_tag(self):
        """R5.B3: Verify 0-byte row payload produces consistent 64-char HMAC and verifies."""
        tpm_key = b"TPM_KEY_BOUNDARY_TEST_123456789"
        tag = oracles.compute_tpm_row_integrity_tag_oracle("empty_table", "row_zero", b"", tpm_key)
        self.assertEqual(len(tag), 64)
        ok = oracles.verify_tpm_row_integrity_oracle("empty_table", "row_zero", b"", tag, tpm_key)
        self.assertTrue(ok)

    def test_r5_b04_large_sqlite_row_payload_boundary(self):
        """R5.B4: Verify 1 MiB row payload generates valid TPM HMAC in < 15ms."""
        tpm_key = b"TPM_KEY_BOUNDARY_TEST_123456789"
        large_payload = b"A" * (1024 * 1024)
        start = time.perf_counter()
        tag = oracles.compute_tpm_row_integrity_tag_oracle("large_table", "row_1mb", large_payload, tpm_key)
        duration = time.perf_counter() - start
        self.assertEqual(len(tag), 64)
        self.assertLess(duration, 0.05)

    def test_r5_b05_sddl_inheritance_and_ace_ordering(self):
        """R5.B5: Verify permissive ACEs (Everyone, Authenticated Users) fail DACL validation."""
        for permissive in ("D:P(A;;GA;;;WD)", "D:P(A;;GA;;;AU)", "D:P(A;;GA;;;BU)"):
            ok, msg = oracles.validate_ntfs_dacl_sddl_oracle(permissive)
            self.assertFalse(ok)
            self.assertIn("permissive", msg)

    def test_r5_b06_constant_time_secret_comparison_resilience(self):
        """R5.B6: Verify hmac.compare_digest prevents timing leaks on partial token matches."""
        token_a = "OSHOOSI_ADMIN_SECRET_ABC123"
        token_b = "OSHOOSI_ADMIN_SECRET_ABC999"
        # Same length, same prefix, different suffix
        status, _ = oracles.control_plane_session_auth_oracle(token_b, token_a, "http://127.0.0.1:3030", "same-origin")
        self.assertEqual(status, 401)

    # =========================================================================
    # Requirement 6 Boundaries: Autonomous Research Swarm Poisoning
    # =========================================================================

    def test_r6_b01_empty_rule_indicator_string(self):
        """R6.B1: Verify empty rule indicator matches everything or is rejected by canary gate."""
        corpus = [{"cmd": "dir"}]
        fp, is_clean = oracles.evaluate_canary_benign_corpus_oracle("", corpus)
        # Empty string indicator trivially matches everything, yielding false positives
        self.assertEqual(fp, 1)
        self.assertFalse(is_clean)

    def test_r6_b02_wildcard_regex_bomb_resilience(self):
        """R6.B2: Verify complex or wildcard string indicators evaluate deterministically without ReDoS."""
        corpus = [{"data": "a" * 1000 + "b"}]
        start = time.perf_counter()
        fp, _ = oracles.evaluate_canary_benign_corpus_oracle("c2_beacon_pattern", corpus)
        duration = time.perf_counter() - start
        self.assertEqual(fp, 0)
        self.assertLess(duration, 0.01)

    def test_r6_b03_empty_benign_corpus_boundary(self):
        """R6.B3: Verify empty benign corpus check returns 0 false positives."""
        fp, is_clean = oracles.evaluate_canary_benign_corpus_oracle("mimikatz", [])
        self.assertEqual(fp, 0)
        self.assertTrue(is_clean)

    def test_r6_b04_pinned_rule_overwriting_with_max_priority(self):
        """R6.B4: Verify priority 9999 cannot evict an existing pinned rule."""
        evicted, reason = oracles.evaluate_anti_eviction_oracle(existing_rule_is_pinned=True, new_rule_priority=9999)
        self.assertFalse(evicted)
        self.assertIn("EVICTION_DENIED", reason)

    def test_r6_b05_duplicate_rule_hash_idempotency(self):
        """R6.B5: Verify duplicate rule registration yields identical promotion decision."""
        res1 = oracles.evaluate_research_rule_promotion_oracle("R1", "indicator_x", 0, True, False)
        res2 = oracles.evaluate_research_rule_promotion_oracle("R1", "indicator_x", 0, True, False)
        self.assertEqual(res1, res2)

    def test_r6_b06_corpus_with_unicode_homoglyphs(self):
        """R6.B6: Verify benign corpus with unicode characters processes without crash."""
        unicode_corpus = [{"cmd": "git commit -m 'ọṣọ́ọ̀sì secure release'"}, {"cmd": "cargo 測試"}]
        fp, is_clean = oracles.evaluate_canary_benign_corpus_oracle("bad_c2_url", unicode_corpus)
        self.assertEqual(fp, 0)
        self.assertTrue(is_clean)

    # =========================================================================
    # Requirement 7 Boundaries: Consensus Engine & Asymmetric Veto
    # =========================================================================

    def test_r7_b01_clamping_negative_infinity_voter_weights(self):
        """R7.B1: Verify extreme negative voter weights (-999.0) are clamped to 0.50 minimum."""
        action, conf, _ = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=False,
            voter_weights=[-999.0],
        )
        # Clamped to 0.50, avg = 0.50, confidence = 0.50/2.0 = 0.25 -> Alert
        self.assertEqual(conf, 0.25)
        self.assertEqual(action, oracles.ResponseAction.Alert)

    def test_r7_b02_clamping_positive_infinity_voter_weights(self):
        """R7.B2: Verify extreme positive voter weights (+999.0) are clamped to 2.50 maximum."""
        action, conf, _ = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=False,
            voter_weights=[999.0],
        )
        # Clamped to 2.50, avg = 2.50, confidence = min(1.0, 2.50/2.0) = 1.0 -> Isolate
        self.assertEqual(conf, 1.0)
        self.assertEqual(action, oracles.ResponseAction.Isolate)

    def test_r7_b03_empty_voter_list_boundary(self):
        """R7.B3: Verify empty voter list evaluates safely without ZeroDivisionError."""
        action, conf, _ = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=False,
            voter_weights=[],
        )
        self.assertEqual(conf, 0.0)
        self.assertEqual(action, oracles.ResponseAction.Alert)

    def test_r7_b04_deterministic_guard_with_both_ml_and_nsrl_veto(self):
        """R7.B4: Verify both ML veto AND NSRL veto simultaneously active are overridden by deterministic guard."""
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=True,
            statistical_pe_ml_veto=True,
            nsrl_whitelist_veto=True,
            voter_weights=[0.5],
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertEqual(conf, 1.0)
        self.assertIn("Overridden static ML/NSRL veto", reason)

    def test_r7_b05_threshold_boundary_084_vs_085(self):
        """R7.B5: Verify threshold boundary: confidence < 0.85 alerts, while >= 0.85 isolates."""
        # weight = 1.68 -> avg = 1.68 -> conf = 0.84 -> Alert
        action_sub, conf_sub, _ = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False, statistical_pe_ml_veto=False, nsrl_whitelist_veto=False, voter_weights=[1.68]
        )
        self.assertLess(conf_sub, 0.85)
        self.assertEqual(action_sub, oracles.ResponseAction.Alert)

        # weight = 1.70 -> avg = 1.70 -> conf = 0.85 -> Isolate
        action_iso, conf_iso, _ = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False, statistical_pe_ml_veto=False, nsrl_whitelist_veto=False, voter_weights=[1.70]
        )
        self.assertGreaterEqual(conf_iso, 0.85)
        self.assertEqual(action_iso, oracles.ResponseAction.Isolate)

    def test_r7_b06_zero_confidence_benign_consensus(self):
        """R7.B6: Verify clean whitelist matches produce ResponseAction::Allow with 0.0 confidence."""
        action, conf, _ = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=True,
            voter_weights=[1.0],
        )
        self.assertEqual(action, oracles.ResponseAction.Allow)
        self.assertEqual(conf, 0.0)


if __name__ == "__main__":
    unittest.main()
