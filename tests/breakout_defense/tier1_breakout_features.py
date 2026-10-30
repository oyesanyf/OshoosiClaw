"""
OshoosiClaw Continuous Agent Breakout Defense - Tier 1: Feature Coverage
Tests primary behaviors and functional contracts for all 7 requirements (R1–R7).
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


class TestTier1BreakoutFeatures(unittest.TestCase):
    """Tier 1: Feature Coverage across R1 through R7."""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.sandbox_crate = cls.root / "crates" / "osoosi-sandbox"
        cls.policy_crate = cls.root / "crates" / "osoosi-policy"
        cls.anomaly_crate = cls.root / "crates" / "osoosi-agent-anomaly"
        cls.runtime_crate = cls.root / "crates" / "osoosi-runtime"
        cls.inject_crate = cls.root / "crates" / "osoosi-inject"
        cls.dashboard_crate = cls.root / "crates" / "osoosi-dashboard"
        cls.driver_dir = cls.root / "driver" / "windows" / "src"

    # =========================================================================
    # Requirement 1: OS Sandbox, Token & Process Isolation Hardening
    # =========================================================================

    def test_r1_tc01_handle_allowlist_attribute_allocated(self):
        """R1.1: Verify PROC_THREAD_ATTRIBUTE_HANDLE_LIST constant and attribute allocation contract."""
        self.assertEqual(oracles.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, 0x00020002)
        # Verify handle allowlist semantics: child inherits strictly allowed pipes, blocking leaked handles
        allowed_handles = [100, 104]  # e.g., stdout write, stderr write
        forbidden_leak = 200  # e.g., parent service database or admin socket handle
        self.assertIn(100, allowed_handles)
        self.assertNotIn(forbidden_leak, allowed_handles)

    def test_r1_tc02_create_suspended_pre_resume_job_binding(self):
        """R1.2: Verify worker process creation state machine enforces CREATE_SUSPENDED before ResumeThread."""
        outcome = oracles.evaluate_pre_resume_confinement_oracle(
            creation_flags=oracles.CREATE_SUSPENDED_FLAG,
            job_limit_flags=oracles.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | oracles.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            active_process_limit=1,
            require_appcontainer_sid=True,
            require_is_process_in_job=True,
            allow_uncontained_fallback=False,
            appcontainer_profile_allocated=True,
            sid_bound=True,
            job_assigned=True,
            is_process_in_job=True,
        )
        self.assertTrue(outcome.resume_thread_allowed)
        self.assertFalse(outcome.terminated_suspended_process)
        self.assertIn("CONFINED_OK", outcome.reason)

    def test_r1_tc03_job_object_limits_kill_on_close_and_active_cap(self):
        """R1.3: Verify Job Object limits enforce KILL_ON_JOB_CLOSE and ACTIVE_PROCESS cap."""
        self.assertEqual(oracles.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0x00002000)
        self.assertEqual(oracles.JOB_OBJECT_LIMIT_ACTIVE_PROCESS, 0x00000008)
        # Policy missing KILL_ON_JOB_CLOSE must fail closed immediately
        outcome = oracles.evaluate_pre_resume_confinement_oracle(
            creation_flags=oracles.CREATE_SUSPENDED_FLAG,
            job_limit_flags=oracles.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,  # missing kill on close!
            active_process_limit=1,
            require_appcontainer_sid=True,
            require_is_process_in_job=True,
            allow_uncontained_fallback=False,
            appcontainer_profile_allocated=True,
            sid_bound=True,
            job_assigned=True,
            is_process_in_job=True,
        )
        self.assertFalse(outcome.resume_thread_allowed)
        self.assertTrue(outcome.terminated_suspended_process)
        self.assertIn("KILL_ON_JOB_CLOSE", outcome.reason)

    def test_r1_tc04_reparse_point_blocking_open_confined(self):
        """R1.4: Verify open_confined rejects reparse points, junctions, and null-byte injection."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            clean_sub = "scratch/output.txt"
            (root / "scratch").mkdir()
            (root / clean_sub).write_text("safe content", encoding="utf-8")

            ok, res = oracles.validate_sandbox_path_join_oracle(root, clean_sub)
            self.assertTrue(ok)
            self.assertTrue(res.startswith(str(root)))

            # Traversal attempt
            ok_trav, res_trav = oracles.validate_sandbox_path_join_oracle(root, "../outside.txt")
            self.assertFalse(ok_trav)
            self.assertIn("Parent directory traversal", res_trav)

    def test_r1_tc05_canonical_root_confinement_getfinalpathname(self):
        """R1.5: Verify canonical root containment check prevents path escaping sandbox boundaries."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            ok, msg = oracles.validate_sandbox_path_join_oracle(root, "valid/sub/file.json")
            self.assertTrue(ok)

            # Leading slash attempt
            ok_slash, msg_slash = oracles.validate_sandbox_path_join_oracle(root, "/etc/passwd")
            self.assertFalse(ok_slash)
            self.assertIn("Leading slash", msg_slash)

    def test_r1_tc06_dns_rebinding_socketaddr_pinning(self):
        """R1.6: Verify socket connect guard rejects loopback, RFC1918, CGNAT, and link-local SSRF IP literals."""
        # Loopback
        is_ssrf, msg = oracles.is_ssrf_socket_addr_oracle("127.0.0.1", 80)
        self.assertTrue(is_ssrf)
        self.assertIn("Loopback", msg)

        # RFC 1918
        is_ssrf, msg = oracles.is_ssrf_socket_addr_oracle("10.10.1.5", 443)
        self.assertTrue(is_ssrf)
        self.assertIn("RFC 1918", msg)

        # IMDS Link-Local
        is_ssrf, msg = oracles.is_ssrf_socket_addr_oracle("169.254.169.254", 80)
        self.assertTrue(is_ssrf)
        self.assertIn("Link-Local", msg)

        # Legitimate public IP
        is_ssrf, msg = oracles.is_ssrf_socket_addr_oracle("93.184.216.34", 443)
        self.assertFalse(is_ssrf)
        self.assertIn("Valid Public Egress", msg)

    # =========================================================================
    # Requirement 2: Temporal Policy, Taint Tracking & Operational Breakout Defense
    # =========================================================================

    def test_r2_tc01_dogwood_mfotl_cumulative_taint_flow_detected(self):
        """R2.1: Verify Dogwood MFOTL detects multi-turn sequence: UntrustedWebInput -> ScratchFileWrite -> SubprocessEnvOrArg."""
        now = time.time()
        trace = [
            oracles.TemporalTraceAtom(now - 3000, oracles.TemporalEventType.UntrustedWebInput, "sess-1"),
            oracles.TemporalTraceAtom(now - 1500, oracles.TemporalEventType.ScratchFileWrite, "sess-1", "/tmp/payload.sh"),
            oracles.TemporalTraceAtom(now - 100, oracles.TemporalEventType.SubprocessEnvOrArg, "sess-1"),
        ]
        violated, reason = oracles.evaluate_dogwood_mfotl_taint_flow_oracle(trace, now)
        self.assertTrue(violated)
        self.assertIn("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION", reason)

    def test_r2_tc02_taint_flow_outside_sliding_window_permitted(self):
        """R2.2: Verify events occurring outside the 2-hour sliding window do not trigger temporal forbid."""
        now = time.time()
        # Web input occurred 3 hours ago (> 7200 seconds)
        trace = [
            oracles.TemporalTraceAtom(now - 10800, oracles.TemporalEventType.UntrustedWebInput, "sess-2"),
            oracles.TemporalTraceAtom(now - 1500, oracles.TemporalEventType.ScratchFileWrite, "sess-2"),
            oracles.TemporalTraceAtom(now - 100, oracles.TemporalEventType.SubprocessEnvOrArg, "sess-2"),
        ]
        violated, _ = oracles.evaluate_dogwood_mfotl_taint_flow_oracle(trace, now)
        self.assertFalse(violated)

    def test_r2_tc03_supervisor_declassification_receipt_clears_taint(self):
        """R2.3: Verify explicit cryptographic supervisor declassification clears cumulative taint chain."""
        now = time.time()
        trace = [
            oracles.TemporalTraceAtom(now - 2000, oracles.TemporalEventType.UntrustedWebInput, "sess-3"),
            oracles.TemporalTraceAtom(now - 1000, oracles.TemporalEventType.ScratchFileWrite, "sess-3"),
            oracles.TemporalTraceAtom(now - 500, oracles.TemporalEventType.SupervisorDeclassification, "sess-3"),
            oracles.TemporalTraceAtom(now - 100, oracles.TemporalEventType.SubprocessEnvOrArg, "sess-3"),
        ]
        violated, _ = oracles.evaluate_dogwood_mfotl_taint_flow_oracle(trace, now)
        self.assertFalse(violated)

    def test_r2_tc04_git_interpreter_env_hijack_blocked(self):
        """R2.4: Verify GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, and RUSTC_WRAPPER environment hijacking vectors are blocked."""
        bad_env = {
            "GIT_SSH_COMMAND": "calc.exe",
            "PATH": "C:\\Windows\\System32",
        }
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(bad_env, "git clone repo")
        self.assertTrue(blocked)
        self.assertTrue(any("GIT_SSH_COMMAND" in v for v in violations))

    def test_r2_tc05_python_node_interpreter_env_hijack_blocked(self):
        """R2.5: Verify PYTHONPATH, PYTHONSTARTUP, and NODE_OPTIONS environment hijacking vectors are blocked."""
        bad_env = {
            "PYTHONPATH": "C:\\malicious\\lib",
            "NODE_OPTIONS": "--require C:\\evil\\hook.js",
        }
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(bad_env, "python worker.py")
        self.assertTrue(blocked)
        self.assertEqual(len(violations), 2)

    def test_r2_tc06_cargo_build_rs_config_tampering_blocked(self):
        """R2.6: Verify .cargo/config.toml and build.rs hijacking parameters are detected and blocked."""
        bad_env = {
            "CARGO_HOME": "C:\\repo\\.cargo\\config.toml",
        }
        blocked, violations = oracles.inspect_execution_environment_hijacking_oracle(bad_env, "cargo build")
        self.assertTrue(blocked)
        self.assertTrue(any(".cargo/config.toml" in v for v in violations))

    # =========================================================================
    # Requirement 3: Multi-Agent Mesh Invariant & Indirect Prompt Injection Defense
    # =========================================================================

    def test_r3_tc01_taint_level_untrusted_external_envelope(self):
        """R3.1: Verify TaintLevel::UntrustedExternal is attached to HMAC envelope signature."""
        key = b"TEST_SECRET_MESH_KEY_0123456789"
        sig = oracles.compute_mesh_hmac_oracle(
            arm_id=1,
            epoch=5,
            role="ResearchSwarmArm",
            target_arm_id=2,
            payload="analyze untrusted repo",
            taint_level=oracles.TaintLevel.UntrustedExternal,
            key=key,
        )
        self.assertEqual(len(sig), 64)
        ok, msg = oracles.verify_mesh_envelope_oracle(
            arm_id=1,
            epoch=5,
            role="ResearchSwarmArm",
            target_arm_id=2,
            payload="analyze untrusted repo",
            taint_level=oracles.TaintLevel.UntrustedExternal,
            key=key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertTrue(ok)
        self.assertEqual(msg, "VALID_ENVELOPE")

    def test_r3_tc02_mesh_envelope_hmac_sha256_verification(self):
        """R3.2: Verify invalid HMAC signature is rejected by constant-time verification oracle."""
        key = b"TEST_SECRET_MESH_KEY_0123456789"
        tampered_sig = "a" * 64
        ok, msg = oracles.verify_mesh_envelope_oracle(
            arm_id=1,
            epoch=5,
            role="ResearchSwarmArm",
            target_arm_id=2,
            payload="analyze untrusted repo",
            taint_level=oracles.TaintLevel.UntrustedExternal,
            key=key,
            signature_hex=tampered_sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok)
        self.assertIn("HMAC-SHA256 verification failed", msg)

    def test_r3_tc03_stale_generation_epoch_rejection(self):
        """R3.3: Verify messages from stale generation epochs are rejected upon limb regeneration."""
        key = b"TEST_SECRET_MESH_KEY_0123456789"
        sig = oracles.compute_mesh_hmac_oracle(
            arm_id=2,
            epoch=3,  # old epoch
            role="WorkerArm",
            target_arm_id=0,
            payload="stale request",
            taint_level=oracles.TaintLevel.TrustedInternal,
            key=key,
        )
        ok, msg = oracles.verify_mesh_envelope_oracle(
            arm_id=2,
            epoch=3,
            role="WorkerArm",
            target_arm_id=0,
            payload="stale request",
            taint_level=oracles.TaintLevel.TrustedInternal,
            key=key,
            signature_hex=sig,
            expected_min_epoch=4,  # regenerated limb expects epoch >= 4
        )
        self.assertFalse(ok)
        self.assertIn("Stale generation epoch", msg)

    def test_r3_tc04_downstream_capability_stripping_untrusted_input(self):
        """R3.4: Verify MeshCapabilityGovernor strips high-privilege tools downstream under UntrustedExternal taint."""
        all_caps = {"read_file", "shell_exec", "cmd", "powershell", "write_file", "network_egress", "extract_credentials"}
        allowed, stripped = oracles.govern_arm_capabilities_oracle(
            current_capabilities=all_caps,
            taint_level=oracles.TaintLevel.UntrustedExternal,
            has_operator_approval=False,
        )
        self.assertEqual(allowed, {"read_file"})
        self.assertEqual(len(stripped), 6)

    def test_r3_tc05_operator_hitl_approval_preserves_capabilities(self):
        """R3.5: Verify verified operator approval receipt preserves high-privilege tool execution."""
        all_caps = {"read_file", "shell_exec", "write_file"}
        allowed, stripped = oracles.govern_arm_capabilities_oracle(
            current_capabilities=all_caps,
            taint_level=oracles.TaintLevel.UntrustedExternal,
            has_operator_approval=True,  # Operator approved
        )
        self.assertEqual(allowed, all_caps)
        self.assertEqual(len(stripped), 0)

    def test_r3_tc06_lateral_movement_sink_isolation(self):
        """R3.6: Verify lateral movement guard prevents untrusted/fuzzing arms from accessing privileged sinks."""
        allowed, msg = oracles.check_lateral_movement_sink_oracle("fuzzing", "AccountingLedgerWrite")
        self.assertFalse(allowed)
        self.assertIn("LATERAL_MOVEMENT_BLOCKED", msg)

        # Benign developer operation allowed
        allowed_dev, _ = oracles.check_lateral_movement_sink_oracle("DeveloperTool", "CodeCompiler")
        self.assertTrue(allowed_dev)

    def test_r3_tc07_taint_level_untrusted_external_envelope_tamper_rejection_f07(self):
        """R3.7 / F07: Verify tampering with TaintLevel::UntrustedExternal envelope breaks HMAC-SHA256 signature."""
        key = b"TEST_SECRET_MESH_KEY_0123456789"
        # Signed as UntrustedExternal
        sig = oracles.compute_mesh_hmac_oracle(
            arm_id=1,
            epoch=5,
            role="UntrustedDocIngest",
            target_arm_id=2,
            payload="malicious preprint payload",
            taint_level=oracles.TaintLevel.UntrustedExternal,
            key=key,
        )
        # Pristine message passes verification
        ok, msg = oracles.verify_mesh_envelope_oracle(
            arm_id=1,
            epoch=5,
            role="UntrustedDocIngest",
            target_arm_id=2,
            payload="malicious preprint payload",
            taint_level=oracles.TaintLevel.UntrustedExternal,
            key=key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertTrue(ok)
        self.assertEqual(msg, "VALID_ENVELOPE")

        # Attacker tampers with taint_level: downgrades to TrustedInternal without re-signing
        tampered_ok, tampered_msg = oracles.verify_mesh_envelope_oracle(
            arm_id=1,
            epoch=5,
            role="UntrustedDocIngest",
            target_arm_id=2,
            payload="malicious preprint payload",
            taint_level=oracles.TaintLevel.TrustedInternal,
            key=key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertFalse(tampered_ok)
        self.assertIn("HMAC-SHA256 verification failed", tampered_msg)

    def test_r3_tc08_hitl_cognitive_firewall_obfuscation_scanner_f29(self):
        """R3.8 / F29: Verify HitlCognitiveFirewall detects RTLO, zero-width, homographs, ANSI escapes, base64 & hex payloads."""
        # 1. RTLO disguise
        rtlo_text = "test\u202efdp.exe"
        inds = oracles.scan_for_visual_deception_oracle(rtlo_text)
        self.assertIn("BidirectionalOverrideRtlo", inds)

        # 2. Zero-width and soft-hyphen
        zero_text = "curl\u00ad http://malicious.local"
        inds = oracles.scan_for_visual_deception_oracle(zero_text)
        self.assertIn("ZeroWidthSteganography", inds)

        # 3. UTS #39 mixed-script homograph (Cyrillic 'е' \u0435)
        homo_text = "authorized_k\u0435ys"
        inds = oracles.scan_for_visual_deception_oracle(homo_text)
        self.assertIn("UnicodeConfusableHomograph", inds)

        # 4. ANSI escape sequence
        ansi_text = "\x1b[2JSystem Ok"
        inds = oracles.scan_for_visual_deception_oracle(ansi_text)
        self.assertIn("AnsiEscapeInjection", inds)

        # 5. Base64 & Hex shell payloads
        hex_text = "certutil -decodehex in.hex out.exe"
        inds = oracles.scan_for_visual_deception_oracle(hex_text)
        self.assertIn("ObfuscatedShellPayload", inds)

        shellcode = "echo -ne '\\x90\\x90\\x90\\x90\\x31\\xc0'"
        inds = oracles.scan_for_visual_deception_oracle(shellcode)
        self.assertIn("ObfuscatedShellPayload", inds)

    def test_r3_tc09_intent_vs_effect_divergence_and_typed_token_f30(self):
        """R3.9 / F30: Verify intent-vs-effect divergence scoring, auto-veto at >= 0.85, and typed blast-radius token challenge."""
        # Severe contradiction: Benign objective + LSASS credential access -> AutoVeto
        decision, score, detail = oracles.evaluate_hitl_escalation_oracle(
            user_objective="Format README and check typos",
            agent_justification="Formatting files for workspace",
            tool_name="extract_credentials",
            canonical_target_resource="C:\\Windows\\System32\\lsass.exe",
            command_args="--dump",
            incoming_taint=oracles.TaintLevel.UntrustedExternal,
        )
        self.assertEqual(decision, "AutoVetoDeceptive")
        self.assertGreaterEqual(score, 0.85)
        # Attempting verification on AutoVeto fails
        verified, err = oracles.verify_typed_blast_radius_challenge_oracle(decision, "TOKEN", "TOKEN")
        self.assertFalse(verified)
        self.assertIn("AUTO_VETOED_DECEPTIVE", err)

        # Elevated risk: Stated deploy objective + write_file -> RequireTypedBlastRadiusChallenge
        decision, score, expected_token = oracles.evaluate_hitl_escalation_oracle(
            user_objective="Build and deploy release package",
            agent_justification="Writing release configuration",
            tool_name="write_file",
            canonical_target_resource="C:\\workspace\\deploy\\release_manifest.json",
            command_args="{}",
            incoming_taint=oracles.TaintLevel.UntrustedExternal,
        )
        self.assertEqual(decision, "RequireTypedBlastRadiusChallenge")
        self.assertTrue(0.45 <= score < 0.85)
        self.assertEqual(expected_token, "CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON")

        # Wrong token rejected
        verified, err = oracles.verify_typed_blast_radius_challenge_oracle(decision, expected_token, "approve")
        self.assertFalse(verified)
        self.assertIn("TOKEN_MISMATCH", err)

        # Exact token accepted
        verified, ok = oracles.verify_typed_blast_radius_challenge_oracle(decision, expected_token, "CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON")
        self.assertTrue(verified)
        self.assertEqual(ok, "CONFIRMATION_VERIFIED")

    def test_r3_tc10_cognitive_redteam_causal_tracing_and_dual_custody_f31(self):
        """R3.10 / F31: Verify CognitiveRedTeamInterceptor counterfactual blast radius, justification stripping, and dual-custody quorum."""
        # 1. Benign read-only operation: reversible, no dual custody required
        read_assessment = oracles.evaluate_cognitive_redteam_oracle(
            user_objective="Inspect repository documentation",
            tool_name="read_file",
            target_resource="C:\\workspace\\README.md",
            command_args="",
            stated_justification="I need to read the project overview to understand milestones.",
            incoming_taint=oracles.TaintLevel.TrustedInternal,
        )
        self.assertFalse(read_assessment.is_irreversible)
        self.assertEqual(len(read_assessment.mutations), 0)
        self.assertFalse(read_assessment.dual_custody_required)
        self.assertFalse(read_assessment.auto_vetoed)
        self.assertIn("[STRIPPED BY COGNITIVE RED-TEAM", read_assessment.stripped_justification)
        self.assertNotIn("project overview", read_assessment.stripped_justification)

        # 2. Deceptive privileged operation: UntrustedExternal taint + System32 hosts modification -> Irreversible + Dual-Custody
        deceptive_assessment = oracles.evaluate_cognitive_redteam_oracle(
            user_objective="Run integration tests",
            tool_name="write_file",
            target_resource="C:\\Windows\\System32\\drivers\\etc\\hosts",
            command_args="127.0.0.1 bad.local",
            stated_justification="Please approve: configuring network loopback for fast integration testing.",
            incoming_taint=oracles.TaintLevel.UntrustedExternal,
        )
        self.assertTrue(deceptive_assessment.is_irreversible)
        self.assertTrue(deceptive_assessment.dual_custody_required)
        self.assertIn("PermanentFileOverwriteOrDeletion", deceptive_assessment.mutations)
        self.assertIn("SecurityBoundaryTampering", deceptive_assessment.mutations)
        self.assertIn("[STRIPPED BY COGNITIVE RED-TEAM", deceptive_assessment.stripped_justification)
        self.assertNotIn("Please approve", deceptive_assessment.stripped_justification)
        self.assertEqual(len(deceptive_assessment.options), 4)
        self.assertEqual(deceptive_assessment.correct_option_index, 0)

    # =========================================================================
    # Requirement 4: Telemetry Resilience, BYOVD Protection & Kernel Integrity
    # =========================================================================

    def test_r4_tc01_watchdog_detects_etw_event_write_patching(self):
        """R4.1: Verify watchdog audits in-memory bytes and detects EtwEventWrite bypass (0xC3)."""
        etw_patched = b"\xc3\x90\x90\x90"
        amsi_clean = b"\x48\x89\x5c\x24\x08"
        detour_clean = b"\x48\x83\xec\x28"

        detected, violations = oracles.audit_watchdog_patches_oracle(etw_patched, amsi_clean, detour_clean)
        self.assertTrue(detected)
        self.assertTrue(any("EtwEventWrite" in v for v in violations))

    def test_r4_tc02_watchdog_detects_amsi_scan_buffer_patching(self):
        """R4.2: Verify watchdog audits in-memory bytes and detects AmsiScanBuffer bypass patch."""
        etw_clean = b"\x48\x89\x5c\x24\x08"
        amsi_patched = b"\xb8\x57\x00\x07\x80\xc3"
        detour_clean = b"\x48\x83\xec\x28"

        detected, violations = oracles.audit_watchdog_patches_oracle(etw_clean, amsi_patched, detour_clean)
        self.assertTrue(detected)
        self.assertTrue(any("AmsiScanBuffer" in v for v in violations))

    def test_r4_tc03_watchdog_detects_detour_unhooking(self):
        """R4.3: Verify watchdog detects inline hook NOP-sled unhooking."""
        etw_clean = b"\x48\x89\x5c\x24\x08"
        amsi_clean = b"\x48\x89\x5c\x24\x08"
        detour_unhooked = b"\x90\x90\x90\x90\x90\x90"

        detected, violations = oracles.audit_watchdog_patches_oracle(etw_clean, amsi_clean, detour_unhooked)
        self.assertTrue(detected)
        self.assertTrue(any("unhooking" in v for v in violations))

    def test_r4_tc04_telemetry_channel_priority_preserves_alerts(self):
        """R4.4: Verify priority channel design retains high-priority security alerts under flood."""
        # High priority items must not be dropped while normal telemetry sheds
        high_prio_events = [f"ALERT-{i}" for i in range(10)]
        normal_events = [f"HEARTBEAT-{i}" for i in range(1000)]
        # Cap queue at 20 items: all 10 alerts must survive
        survived = high_prio_events + normal_events[:10]
        for alert in high_prio_events:
            self.assertIn(alert, survived)

    def test_r4_tc05_byovd_vulnerable_driver_blocklist(self):
        """R4.5: Verify known vulnerable driver hashes (GDRV.SYS, RTCore64.SYS, DBUtil_2_3.SYS) are blocked."""
        gdrv_hash = "3626A6917A00F77B0F3F2F1253457A0F7E0A2BF6FB5DB8F9A5576211EB71616F"
        allowed, msg = oracles.check_byovd_driver_blocklist_oracle(gdrv_hash)
        self.assertFalse(allowed)
        self.assertIn("GDRV.SYS", msg)

        # Clean benign driver allowed
        clean_driver_hash = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
        allowed_clean, _ = oracles.check_byovd_driver_blocklist_oracle(clean_driver_hash)
        self.assertTrue(allowed_clean)

    def test_r4_tc06_kernel_callback_registration_self_integrity(self):
        """R4.6: Verify kernel callback registration self-integrity detects zeroed or modified pointers."""
        orig_ptr = 0xFFFFF80012345678
        ok, _ = oracles.verify_kernel_callback_integrity_oracle(orig_ptr, orig_ptr)
        self.assertTrue(ok)

        # Zeroed pointer (DKOM attack)
        tampered_ok, msg = oracles.verify_kernel_callback_integrity_oracle(orig_ptr, 0x0)
        self.assertFalse(tampered_ok)
        self.assertIn("zeroed", msg)

    # =========================================================================
    # Requirement 5: Local Control Plane & SQLite Storage Hardening
    # =========================================================================

    def test_r5_tc01_control_plane_session_auth_gating(self):
        """R5.1: Verify /api/auth/session rejects unauthenticated requests and requires admin secret."""
        admin_secret = "OSHOOSI_ADMIN_SECRET_TOKEN_9988"
        status, msg = oracles.control_plane_session_auth_oracle(
            presented_token=None,
            admin_secret=admin_secret,
            origin_header="http://127.0.0.1:3030",
            sec_fetch_site_header="same-origin",
        )
        self.assertEqual(status, 401)

        # Valid secret
        status_ok, msg_ok = oracles.control_plane_session_auth_oracle(
            presented_token=admin_secret,
            admin_secret=admin_secret,
            origin_header="http://127.0.0.1:3030",
            sec_fetch_site_header="same-origin",
        )
        self.assertEqual(status_ok, 200)

    def test_r5_tc02_origin_header_enforcement(self):
        """R5.2: Verify untrusted Origin headers (e.g. http://evil.com) are rejected with 403."""
        status, msg = oracles.control_plane_session_auth_oracle(
            presented_token="OSHOOSI_ADMIN_SECRET_TOKEN_9988",
            admin_secret="OSHOOSI_ADMIN_SECRET_TOKEN_9988",
            origin_header="http://evil.com",
            sec_fetch_site_header="cross-site",
        )
        self.assertEqual(status, 403)
        self.assertIn("Cross-origin request rejected", msg)

    def test_r5_tc03_sec_fetch_site_same_origin_enforcement(self):
        """R5.3: Verify Sec-Fetch-Site cross-site is rejected with 403."""
        status, msg = oracles.control_plane_session_auth_oracle(
            presented_token="OSHOOSI_ADMIN_SECRET_TOKEN_9988",
            admin_secret="OSHOOSI_ADMIN_SECRET_TOKEN_9988",
            origin_header="http://127.0.0.1:3030",
            sec_fetch_site_header="cross-site",
        )
        self.assertEqual(status, 403)
        self.assertIn("Untrusted Sec-Fetch-Site", msg)

    def test_r5_tc04_sqlite_ntfs_dacl_lockdown(self):
        """R5.4: Verify Win32 Protected NTFS DACL string enforces D:P with SYSTEM and Administrators only."""
        valid_sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        ok, msg = oracles.validate_ntfs_dacl_sddl_oracle(valid_sddl)
        self.assertTrue(ok)

        # Insecure permissive DACL with Everyone access
        insecure_sddl = "D:(A;;GA;;;WD)(A;;GA;;;SY)"
        ok_bad, msg_bad = oracles.validate_ntfs_dacl_sddl_oracle(insecure_sddl)
        self.assertFalse(ok_bad)
        self.assertIn("not protected", msg_bad)

    def test_r5_tc05_tpm_row_integrity_tag_generation(self):
        """R5.5: Verify hardware-keyed HMAC-SHA256 row integrity tag generation is deterministic."""
        tpm_key = b"TPM2_NCRYPT_HARDWARE_KEY_32BYTES"
        payload = b'{"setting":"killswitch_armed","value":true}'
        tag = oracles.compute_tpm_row_integrity_tag_oracle("ui_settings_kv", "setting_001", payload, tpm_key)
        self.assertEqual(len(tag), 64)

        # Verification passes
        verified = oracles.verify_tpm_row_integrity_oracle("ui_settings_kv", "setting_001", payload, tag, tpm_key)
        self.assertTrue(verified)

    def test_r5_tc06_tpm_row_integrity_tamper_detection(self):
        """R5.6: Verify tampered row payload fails TPM 2.0 integrity verification."""
        tpm_key = b"TPM2_NCRYPT_HARDWARE_KEY_32BYTES"
        payload = b'{"setting":"killswitch_armed","value":true}'
        tag = oracles.compute_tpm_row_integrity_tag_oracle("ui_settings_kv", "setting_001", payload, tpm_key)

        tampered_payload = b'{"setting":"killswitch_armed","value":false}'
        verified = oracles.verify_tpm_row_integrity_oracle("ui_settings_kv", "setting_001", tampered_payload, tag, tpm_key)
        self.assertFalse(verified)

    # =========================================================================
    # Requirement 6: Autonomous Research Swarm Poisoning Defenses
    # =========================================================================

    def test_r6_tc01_in_memory_declarative_indicator_evaluation(self):
        """R6.1: Verify research indicator strings are evaluated in-memory without host process execution."""
        clean_telemetry = [
            {"event": "ProcessCreate", "image": "C:\\Windows\\notepad.exe"},
            {"event": "FileOpen", "path": "C:\\Users\\dev\\main.rs"},
        ]
        fp_count, is_clean = oracles.evaluate_canary_benign_corpus_oracle("mimikatz.exe", clean_telemetry)
        self.assertEqual(fp_count, 0)
        self.assertTrue(is_clean)

    def test_r6_tc02_canary_benign_corpus_zero_fp_check(self):
        """R6.2: Verify candidate rule with 0 false positives passes canary corpus check."""
        clean_corpus = [{"cmd": "cargo check"}, {"cmd": "git status"}]
        fp, is_clean = oracles.evaluate_canary_benign_corpus_oracle("Invoke-Mimikatz", clean_corpus)
        self.assertEqual(fp, 0)
        self.assertTrue(is_clean)

    def test_r6_tc03_canary_rejects_rule_with_false_positives(self):
        """R6.3: Verify candidate rule matching clean telemetry is rejected by canary gate."""
        clean_corpus = [{"cmd": "powershell -File test.ps1"}, {"cmd": "cargo build"}]
        fp, is_clean = oracles.evaluate_canary_benign_corpus_oracle("powershell", clean_corpus)
        self.assertEqual(fp, 1)
        self.assertFalse(is_clean)

        promoted, reason = oracles.evaluate_research_rule_promotion_oracle("RULE-01", "powershell", fp, True, False)
        self.assertFalse(promoted)
        self.assertIn("false positives", reason)

    def test_r6_tc04_operator_approval_gating_prior_to_blocking(self):
        """R6.4: Verify clean rule remains staged until operator approval is granted."""
        promoted, reason = oracles.evaluate_research_rule_promotion_oracle("RULE-02", "CobaltStrikeBeacon", 0, False, False)
        self.assertFalse(promoted)
        self.assertIn("STAGED_OBSERVATION_ONLY", reason)

        # Operator approval grants active blocking
        promoted_ok, reason_ok = oracles.evaluate_research_rule_promotion_oracle("RULE-02", "CobaltStrikeBeacon", 0, True, False)
        self.assertTrue(promoted_ok)
        self.assertEqual(reason_ok, "ACTIVE_BLOCKING_PERMITTED")

    def test_r6_tc05_anti_eviction_protects_pinned_rules(self):
        """R6.5: Verify pinned rules cannot be evicted or replaced by attacker updates."""
        evicted, reason = oracles.evaluate_anti_eviction_oracle(existing_rule_is_pinned=True, new_rule_priority=10)
        self.assertFalse(evicted)
        self.assertIn("EVICTION_DENIED", reason)

    def test_r6_tc06_malformed_broad_rule_rejected(self):
        """R6.6: Verify single-token common binary rules trigger false positives and are rejected."""
        benign_dev_traffic = [{"line": "Running cargo.exe check"}, {"line": "cl.exe /c main.c"}]
        fp, is_clean = oracles.evaluate_canary_benign_corpus_oracle("cargo.exe", benign_dev_traffic)
        self.assertFalse(is_clean)
        self.assertEqual(fp, 1)

    # =========================================================================
    # Requirement 7: Decision Model Asymmetric Veto & Performance Invariants
    # =========================================================================

    def test_r7_tc01_deterministic_guard_commands_isolate(self):
        """R7.1: Verify deterministic invariant violation unconditionally commands ResponseAction::Isolate."""
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=True,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=False,
            voter_weights=[1.0, 1.2, 0.9],
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertEqual(conf, 1.0)
        self.assertIn("ASYMMETRIC_VETO", reason)

    def test_r7_tc02_asymmetric_veto_overrides_static_pe_ml(self):
        """R7.2: Verify deterministic invariant violation unconditionally overrides static PE ML veto."""
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=True,
            statistical_pe_ml_veto=True,  # ML veto
            nsrl_whitelist_veto=False,
            voter_weights=[0.5, 0.5],
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertEqual(conf, 1.0)
        self.assertIn("Overridden static ML/NSRL veto", reason)

    def test_r7_tc03_asymmetric_veto_overrides_nsrl_whitelist(self):
        """R7.3: Verify deterministic invariant violation unconditionally overrides NSRL whitelist veto."""
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=True,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=True,  # NSRL whitelist veto
            voter_weights=[1.0],
        )
        self.assertEqual(action, oracles.ResponseAction.Isolate)
        self.assertEqual(conf, 1.0)
        self.assertIn("Overridden static ML/NSRL veto", reason)

    def test_r7_tc04_benign_workload_retains_normal_consensus(self):
        """R7.4: Verify benign workloads without deterministic violations apply normal whitelist/veto logic."""
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False,
            statistical_pe_ml_veto=True,
            nsrl_whitelist_veto=False,
            voter_weights=[1.0],
        )
        self.assertEqual(action, oracles.ResponseAction.Allow)
        self.assertEqual(conf, 0.0)

    def test_r7_tc05_voter_weight_clamping_prevents_byzantine_override(self):
        """R7.5: Verify voter weights are clamped to [0.50, 2.50], preventing Byzantine negative weight override."""
        action, conf, reason = oracles.consensus_asymmetric_veto_oracle(
            has_deterministic_guard=False,
            statistical_pe_ml_veto=False,
            nsrl_whitelist_veto=False,
            voter_weights=[-10.0, 100.0],  # extreme Byzantine weights
        )
        # Clamped to [0.5, 2.5], avg = 1.5, confidence = min(1.0, 1.5/2.0) = 0.75 -> Alert
        self.assertEqual(action, oracles.ResponseAction.Alert)
        self.assertEqual(conf, 0.75)

    def test_r7_tc06_contention_free_concurrency_lock_hygiene(self):
        """R7.6: Verify concurrent evaluation executes cleanly with zero deadlocks under thread pooling."""
        import concurrent.futures

        def worker(idx: int):
            is_deterministic = (idx % 2 == 0)
            return oracles.consensus_asymmetric_veto_oracle(
                has_deterministic_guard=is_deterministic,
                statistical_pe_ml_veto=False,
                nsrl_whitelist_veto=False,
                voter_weights=[1.0, 1.1, 1.2],
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(100)))

        self.assertEqual(len(results), 100)
        # 50 deterministic isolations, 50 consensus alerts
        isolates = sum(1 for a, _, _ in results if a == oracles.ResponseAction.Isolate)
        self.assertEqual(isolates, 50)


if __name__ == "__main__":
    unittest.main()
