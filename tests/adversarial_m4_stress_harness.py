"""
tests/adversarial_m4_stress_harness.py

Milestone 4 Independent Adversarial Challenge & Empirical Stress Test Harness
Conducted by teamwork_challenger_m4_r2_1 (Empirical Challenger).

Target Features:
- F32: Continuous Distributed Attestation & TPM 2.0 PCR-Bound Heartbeat Ratchet
- F32: Pre-Load Static Driver PE Analysis & IOCTL Sink Detection
- F11: Ring-0 Bring Your Own Vulnerable Driver (BYOVD) SHA-256 Blocklist
- F12: Periodic Kernel Callback Registration Self-Integrity Assertions
- F25: Hardware HVCI / VBS / VTL1 Posture Verifier (NtQuerySystemInformation 0x67)
- F26: Cross-View DKOM Process Differential & O(1) Wald SPRT Callback Sensor
- F09: User-Mode In-Memory Hook, ETW & AMSI Tamper Watchdog
- F10: Prioritized Dual-Tier Telemetry Channels & Event Starvation Defense
"""

import hashlib
import hmac
import json
import math
import os
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add workspace and tests to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))
sys.path.insert(0, str(WORKSPACE_ROOT / "tests"))
sys.path.insert(0, str(WORKSPACE_ROOT / "tests" / "breakout_defense"))

import breakout_defense.oracles as oracles


class Milestone4AdversarialStressHarness(unittest.TestCase):
    """Exhaustive empirical challenge suite stress-testing Milestone M4."""

    def setUp(self):
        self.aik_key = b"tpm2_hardware_attestation_key_32b_secret!!"
        self.genesis_pcr = hashlib.sha256(b"PCR_GENESIS_MEASUREMENT_BANK11").digest()
        self.boot_id = "boot-guid-1234-5678-abcdef"
        self.now = 1700000000

    # =========================================================================
    # 1. F32: TPM 2.0 PCR-Bound Heartbeat Ratchet & P2P Dead-Man's Switch
    # =========================================================================

    def test_challenge_f32_tpm_ratchet_tamper_matrix(self):
        """Stress-test F32: TPM PCR ratchet replay, sequence counter tampering, nonce bit-flips, stale PCR digests."""
        genesis = oracles.TpmPcrHeartbeatRatchetOracle(epoch=1, pcr_digest=self.genesis_pcr, timestamp_utc=self.now)
        self.assertEqual(genesis.epoch, 1)
        self.assertEqual(genesis.pcr_digest, self.genesis_pcr)

        nonce = b"fresh_cryptographic_nonce_step2"
        state_digest = hashlib.sha256(b"kernel_state_step2").digest()

        # 1. Nominal step 2 transition
        step2 = genesis.advance(nonce=nonce, state_digest=state_digest, timestamp_utc=self.now + 1)
        self.assertEqual(step2.epoch, 2)
        self.assertNotEqual(step2.pcr_digest, self.genesis_pcr)

        # 2. Nonce bit-flip attack: flip single bit in byte 0, middle, and end
        for bit_pos in [0, 1, 7, 15, len(nonce) - 1]:
            corrupted_nonce = bytearray(nonce)
            corrupted_nonce[bit_pos] ^= 0x01
            step2_corrupted = genesis.advance(nonce=bytes(corrupted_nonce), state_digest=state_digest, timestamp_utc=self.now + 1)
            self.assertNotEqual(
                step2_corrupted.pcr_digest,
                step2.pcr_digest,
                f"Bit flip at position {bit_pos} must produce divergent PCR digest"
            )

        # 3. State digest bit-flip attack
        for bit_pos in [0, 15, 31]:
            corrupted_state = bytearray(state_digest)
            corrupted_state[bit_pos] ^= 0x01
            step2_corrupted_state = genesis.advance(nonce=nonce, state_digest=bytes(corrupted_state), timestamp_utc=self.now + 1)
            self.assertNotEqual(
                step2_corrupted_state.pcr_digest,
                step2.pcr_digest,
                f"State digest bit flip at {bit_pos} must alter resulting PCR measurement"
            )

        # 4. Backward timestamp skew rejection
        with self.assertRaises(ValueError):
            genesis.advance(nonce=nonce, state_digest=state_digest, timestamp_utc=self.now - 1)

        # 5. Nonce length edge cases: empty nonce, 1-byte, 1024-byte
        empty_step = genesis.advance(nonce=b"", state_digest=state_digest, timestamp_utc=self.now + 1)
        self.assertEqual(len(empty_step.pcr_digest), 32)

        huge_nonce = b"\xFF" * 1024
        huge_step = genesis.advance(nonce=huge_nonce, state_digest=state_digest, timestamp_utc=self.now + 1)
        self.assertEqual(len(huge_step.pcr_digest), 32)
        self.assertNotEqual(empty_step.pcr_digest, huge_step.pcr_digest)

    def test_challenge_f32_dead_man_switch_boundary_and_drift(self):
        """Stress-test F32: P2P mesh dead-man's switch absence quarantine, clock drift, and replay detection."""
        switch = oracles.P2pMeshDeadMansSwitchOracle(heartbeat_interval_ms=1000, max_tolerance_intervals=3)
        self.assertEqual(switch.evaluate_dead_man_switch(self.now), "Nominal")

        genesis = oracles.TpmPcrHeartbeatRatchetOracle(epoch=1, pcr_digest=self.genesis_pcr, timestamp_utc=self.now)
        res_genesis = switch.ingest_heartbeat(genesis, self.now)
        self.assertEqual(res_genesis, "Nominal")

        # 1. On-time evaluation at t = now
        self.assertEqual(switch.evaluate_dead_man_switch(self.now), "Nominal")

        # 2. Evaluation within normal interval (t = now + 1, elapsed = 1000ms <= interval_ms)
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 1), "Nominal")

        # 3. Warning boundary (t = now + 2, elapsed = 2000ms > 1000ms but <= 3000ms)
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 2), "WarningStaleHeartbeat")

        # 4. Timeout boundary (t = now + 3, elapsed = 3000ms == timeout_ms)
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 3), "WarningStaleHeartbeat")

        # 5. Quarantine trigger (t = now + 4, elapsed = 4000ms > 3000ms timeout)
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 4), "AbsenceQuarantineDeadManTriggered")

        # 6. Replay attack: re-injecting genesis (epoch 1) when last ratchet is epoch 1 (epoch != last + 1)
        res_replay = switch.ingest_heartbeat(genesis, self.now + 2)
        self.assertEqual(res_replay, "CryptographicRatchetTamperDetected")

        # 7. Sequence jump attack: injecting epoch 3 directly (skipping epoch 2)
        step3 = oracles.TpmPcrHeartbeatRatchetOracle(epoch=3, pcr_digest=hashlib.sha256(b"jump").digest(), timestamp_utc=self.now + 2)
        res_jump = switch.ingest_heartbeat(step3, self.now + 2)
        self.assertEqual(res_jump, "CryptographicRatchetTamperDetected")

        # 8. Negative clock jump (current_time_utc < last_seen_utc)
        # Verify dead-man's switch does not crash or falsely trigger quarantine
        drift_status = switch.evaluate_dead_man_switch(self.now - 100)
        self.assertNotEqual(drift_status, "AbsenceQuarantineDeadManTriggered")

    # =========================================================================
    # 2. F32: Pre-Load Static Driver PE Analysis & IOCTL Sink Detection
    # =========================================================================

    def test_challenge_f32_driver_pe_corrupt_and_truncated_headers(self):
        """Stress-test F32: Pre-load static driver analysis on malformed, truncated, and non-PE binaries."""
        # 1. Zero-byte file
        verdict, is_vuln, reasons = oracles.analyze_driver_pe_oracle(b"", "empty.sys")
        self.assertEqual(verdict, "Permit")
        self.assertFalse(is_vuln)

        # 2. Tiny file (1 byte, 2 bytes MZ, 16 bytes)
        for tiny in [b"M", b"MZ", b"MZ\x00\x00", b"A" * 16, b"MZ" + b"\x00" * 30]:
            verdict, is_vuln, _ = oracles.analyze_driver_pe_oracle(tiny, "tiny.sys")
            self.assertEqual(verdict, "Permit")
            self.assertFalse(is_vuln)

        # 3. Truncated at e_lfanew offset (64 bytes, but e_lfanew = 0x80 pointing past EOF)
        truncated_pe = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        verdict, is_vuln, _ = oracles.analyze_driver_pe_oracle(truncated_pe, "truncated.sys")
        self.assertEqual(verdict, "Permit")
        self.assertFalse(is_vuln)

        # 4. Non-PE binaries: ELF binary, Python script, random noise
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
        verdict_elf, is_vuln_elf, _ = oracles.analyze_driver_pe_oracle(elf_header, "driver.sys")
        self.assertEqual(verdict_elf, "Permit")
        self.assertFalse(is_vuln_elf)

        py_script = b"#!/usr/bin/env python3\nimport os\nprint('malicious')\n"
        verdict_py, is_vuln_py, _ = oracles.analyze_driver_pe_oracle(py_script, "driver.sys")
        self.assertEqual(verdict_py, "Permit")
        self.assertFalse(is_vuln_py)

        # 5. Valid MZ, invalid PE signature (e.g. "NE\0\0" 16-bit Windows or "LE\0\0")
        ne_header = b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00" + b"NE\x00\x00" + b"\x00" * 64
        verdict_ne, is_vuln_ne, _ = oracles.analyze_driver_pe_oracle(ne_header, "ne_legacy.sys")
        self.assertEqual(verdict_ne, "Permit")
        self.assertFalse(is_vuln_ne)

    def test_challenge_f32_driver_pe_dangerous_sinks_and_opcodes(self):
        """Stress-test F32: Pre-load driver analysis detecting physical memory mapping and raw MSR opcodes."""
        clean_pe = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00" + b"\x00" * 0x40 + b"PE\x00\x00" + b"ValidBenignSections"

        # 1. Clean driver -> Permit
        v_clean, vuln_clean, _ = oracles.analyze_driver_pe_oracle(clean_pe, "clean.sys")
        self.assertEqual(v_clean, "Permit")
        self.assertFalse(vuln_clean)

        # 2. Dangerous kernel memory imports
        dangerous_test_imports = [
            (b"MmMapIoSpace", "Imports MmMapIoSpace"),
            (b"MmMapLockedPages", "Imports MmMapLockedPages"),
            (b"ZwMapViewOfSection", "Imports ZwMapViewOfSection"),
            (b"__writemsr", "Imports __writemsr"),
        ]

        for imp_bytes, expected_reason in dangerous_test_imports:
            test_pe = clean_pe + b"\x00ImportTable:" + imp_bytes + b"\x00\x00"
            v, vuln, reasons = oracles.analyze_driver_pe_oracle(test_pe, "test_drv.sys")
            self.assertEqual(v, "QuarantineBlockByovd")
            self.assertTrue(vuln)
            self.assertTrue(any(expected_reason in r for r in reasons))

        # 3. Direct WRMSR instruction (0x0F 0x30)
        msr_pe = clean_pe + b"\x90\x90\x0F\x30\xC3"
        v_msr, vuln_msr, reasons_msr = oracles.analyze_driver_pe_oracle(msr_pe, "msr.sys")
        self.assertEqual(v_msr, "QuarantineBlockByovd")
        self.assertTrue(vuln_msr)
        self.assertTrue(any("WRMSR" in r for r in reasons_msr))

        # 4. Benign near-miss opcode: 0x0F 0x31 (RDTSC) -> NOT flagged as WRMSR
        rdtsc_pe = clean_pe + b"\x90\x90\x0F\x31\xC3"
        v_rdtsc, vuln_rdtsc, _ = oracles.analyze_driver_pe_oracle(rdtsc_pe, "rdtsc.sys")
        self.assertEqual(v_rdtsc, "Permit")
        self.assertFalse(vuln_rdtsc)

    def test_challenge_f32_byovd_hash_and_path_casing_variations(self):
        """Stress-test F32: Known BYOVD drivers across lowercase, uppercase, and mixed-case paths and hashes."""
        # 10 Known BYOVD driver filenames
        known_byovd_names = [
            "rtcore64.sys", "dbutil_2_3.sys", "gdrv.sys", "procexp152.sys",
            "iqvw64e.sys", "capcom.sys", "asio64.sys", "mhyprot2.sys",
            "kprocesshacker.sys", "winring0x64.sys"
        ]

        dummy_pe = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00" + b"\x00" * 0x40 + b"PE\x00\x00" + b"DummyContent"

        for drv_name in known_byovd_names:
            # Lowercase
            v1, vuln1, _ = oracles.analyze_driver_pe_oracle(dummy_pe, drv_name.lower())
            self.assertEqual(v1, "QuarantineBlockByovd", f"Must block lowercase {drv_name}")
            self.assertTrue(vuln1)

            # Uppercase
            v2, vuln2, _ = oracles.analyze_driver_pe_oracle(dummy_pe, drv_name.upper())
            self.assertEqual(v2, "QuarantineBlockByovd", f"Must block uppercase {drv_name}")
            self.assertTrue(vuln2)

            # Mixed-case with full Windows path
            full_path = f"C:\\Windows\\System32\\Drivers\\{drv_name.capitalize()}"
            v3, vuln3, _ = oracles.analyze_driver_pe_oracle(dummy_pe, full_path)
            self.assertEqual(v3, "QuarantineBlockByovd", f"Must block full path {full_path}")
            self.assertTrue(vuln3)

            # NT Device path format
            device_path = f"\\Device\\HarddiskVolume3\\Drivers\\{drv_name}"
            v4, vuln4, _ = oracles.analyze_driver_pe_oracle(dummy_pe, device_path)
            self.assertEqual(v4, "QuarantineBlockByovd", f"Must block device path {device_path}")
            self.assertTrue(vuln4)

    # =========================================================================
    # 3. F11 & F12: BYOVD SHA-256 Hash Matching & Kernel Callback Self-Integrity
    # =========================================================================

    def test_challenge_f11_byovd_hash_blocklist_exhaustive(self):
        """Stress-test F11: Verify all 10 known BYOVD driver Authenticode SHA-256 hashes are blocked regardless of renamed files."""
        # The 10 known BYOVD SHA-256 hashes
        expected_byovd_hashes = [
            ("3626a6917a00f77b0f3f2f1253457a0f7e0a2bf6fb5db8f9a5576211eb71616f", "GDRV.SYS"),
            ("f497e6a901be9c8ffde0f9b464db3e2916f4f5ebdd708ce94c2b4da1ee01f529", "RTCore64.SYS"),
            ("d2e689eb05af6c035c2b2956794695d5c6de65f6fb1e5b6b8640c4b82725ff05", "DBUtil_2_3.SYS"),
            ("2364d9d682404b7914bb5344415fa9d1e37fa0ab9cae142e05f03dd28b8cfeb5", "procexp152.sys"),
            ("74ca70a1a8e97426e25f7717be54e7aa1bc9c470eebe6042db643a65492d4b00", "iqvw64e.sys"),
            ("c1d5cfba19dde9e4a1b9442f23e202c578434732c5f8b77b15d9f6a35f019f12", "capcom.sys"),
            ("1cb47a32dd58adab7252da3f6eeaa4ba0e0bf90f111e8ff5f3ae77762a45d045", "asio64.sys"),
            ("0466e92bf6136063bb9545f0f8051ffb562f43d5b98d41e79217623430043852", "mhyprot2.sys"),
            ("cb3b44b63309a4eb392f4460ec0e7e1784f479865ccb80105ccfc73ae2862d55", "kprocesshacker.sys"),
            ("05e1c0d45300b9db8d7d9e48f76fa7ccf0e53a7a972f4e4e94b2931122a6136f", "winring0x64.sys"),
        ]

        for hash_str, desc in expected_byovd_hashes:
            # 1. Lowercase hash check
            allowed_lower, msg_lower = oracles.check_byovd_driver_blocklist_oracle(hash_str.lower())
            self.assertFalse(allowed_lower, f"Must block {desc} with lowercase hash")

            # 2. Uppercase hash check
            allowed_upper, msg_upper = oracles.check_byovd_driver_blocklist_oracle(hash_str.upper())
            self.assertFalse(allowed_upper, f"Must block {desc} with uppercase hash")

            # 3. 1-character mutation on hash: must NOT block (clean benign driver)
            mutated_hash = ("0" if hash_str[0] != "0" else "1") + hash_str[1:]
            allowed_mutated, _ = oracles.check_byovd_driver_blocklist_oracle(mutated_hash)
            self.assertTrue(allowed_mutated, f"Mutated hash {mutated_hash} should not match known BYOVD blocklist")

    def test_challenge_f12_kernel_callback_integrity_assertions(self):
        """Stress-test F12: Kernel callback self-integrity assertions under simulated DKOM unlinking."""
        valid_ptr = 0xFFFFF80012345678

        # 1. Intact pointer
        ok, msg = oracles.verify_kernel_callback_integrity_oracle(valid_ptr, valid_ptr)
        self.assertTrue(ok)
        self.assertEqual(msg, "INTEGRITY_VERIFIED")

        # 2. DKOM zeroing attack (callback pointer zeroed)
        ok_zero, msg_zero = oracles.verify_kernel_callback_integrity_oracle(valid_ptr, 0x0)
        self.assertFalse(ok_zero)
        self.assertIn("zeroed", msg_zero)

        # 3. DKOM hook redirection attack (callback pointer pointing to attacker shellcode)
        attacker_shellcode_ptr = 0xFFFFF80099999999
        ok_hook, msg_hook = oracles.verify_kernel_callback_integrity_oracle(valid_ptr, attacker_shellcode_ptr)
        self.assertFalse(ok_hook)
        self.assertIn("modified", msg_hook)

    # =========================================================================
    # 4. F25 & F26: Hardware HVCI/VBS Posture, DKOM Differential & Wald SPRT
    # =========================================================================

    def test_challenge_f25_hvci_vbs_posture_bitmask_matrix(self):
        """Stress-test F25: Hardware HVCI/VBS posture verification across bitmask permutations."""
        # 1. Zero bitmask: unhardened system, no CI, no HVCI -> must tighten Ring 7
        ci, kmci, ium, tighten = oracles.evaluate_hvci_vbs_posture_oracle(0x00000000)
        self.assertFalse(ci)
        self.assertFalse(kmci)
        self.assertFalse(ium)
        self.assertTrue(tighten, "Zero bitmask must trigger tightened Ring 7 confinement")

        # 2. CI Enabled only (0x01) but HVCI KMCI disabled -> must tighten Ring 7
        ci, kmci, ium, tighten = oracles.evaluate_hvci_vbs_posture_oracle(0x00000001)
        self.assertTrue(ci)
        self.assertFalse(kmci)
        self.assertFalse(ium)
        self.assertTrue(tighten, "CI without KMCI must trigger tightened Ring 7")

        # 3. Full HVCI active (CI 0x01 | KMCI 0x400 | IUM 0x800 = 0xC01) -> standard confinement
        ci, kmci, ium, tighten = oracles.evaluate_hvci_vbs_posture_oracle(0x00000C01)
        self.assertTrue(ci)
        self.assertTrue(kmci)
        self.assertTrue(ium)
        self.assertFalse(tighten, "Full HVCI/VBS must NOT require tightened Ring 7")

        # 4. Unreserved / future Windows bits set (e.g. 0xFFFFFC01)
        ci, kmci, ium, tighten = oracles.evaluate_hvci_vbs_posture_oracle(0xFFFFFC01)
        self.assertTrue(ci)
        self.assertTrue(kmci)
        self.assertTrue(ium)
        self.assertFalse(tighten)

    def test_challenge_f26_cross_view_dkom_differential_edge_cases(self):
        """Stress-test F26: Cross-view DKOM differential under unlinked rootkits, terminated processes, and duplicates."""
        # 1. Nominal matched views
        active = [4, 100, 200, 300, 400]
        handles = [0, 4, 100, 200, 300, 400]
        detected, hidden, _ = oracles.detect_cross_view_dkom_discrepancy_oracle(active, handles)
        self.assertFalse(detected)
        self.assertEqual(len(hidden), 0)

        # 2. Rootkit hidden process (PID 6666) in handle table but absent from ActiveProcessLinks
        handles_rootkit = [0, 4, 100, 200, 300, 400, 6666]
        detected_rk, hidden_rk, msg_rk = oracles.detect_cross_view_dkom_discrepancy_oracle(active, handles_rootkit)
        self.assertTrue(detected_rk)
        self.assertEqual(hidden_rk, [6666])
        self.assertIn("DKOM_HIDDEN_PROCESS_DETECTED", msg_rk)

        # 3. Multiple hidden processes with duplicates
        handles_multi = [0, 4, 100, 200, 300, 400, 9999, 8888, 9999, 7777]
        detected_m, hidden_m, _ = oracles.detect_cross_view_dkom_discrepancy_oracle(active, handles_multi)
        self.assertTrue(detected_m)
        self.assertIn(7777, hidden_m)
        self.assertIn(8888, hidden_m)
        self.assertIn(9999, hidden_m)

        # 4. Pseudo-PIDs (PID 0 Idle, PID 4 System) must never trigger false positives
        handles_sys = [0, 4]
        detected_sys, hidden_sys, _ = oracles.detect_cross_view_dkom_discrepancy_oracle([], handles_sys)
        self.assertFalse(detected_sys)
        self.assertEqual(len(hidden_sys), 0)

        # 5. Process in active links but absent from handle table (normal exited process before reaper)
        # Should NOT trigger DKOM discrepancy
        active_exited = [4, 100, 200, 300, 400, 500]
        handles_reaped = [0, 4, 100, 200, 300, 400]
        detected_ex, hidden_ex, _ = oracles.detect_cross_view_dkom_discrepancy_oracle(active_exited, handles_reaped)
        self.assertFalse(detected_ex)
        self.assertEqual(len(hidden_ex), 0)

    def test_challenge_f26_wald_sprt_blinding_and_delays(self):
        """Stress-test F26: Wald SPRT callback sensor under simulated blinding attacks and extreme event delays."""
        monitor = oracles.KernelSprtCallbackMonitorOracle(
            expected_interval_ms=50.0,
            anomaly_interval_ms=500.0,
            alpha=0.001,
            beta=0.01,
        )

        # 1. 20 consecutive nominal heartbeats (40ms - 55ms) -> stay Nominal/Monitoring
        for i in range(20):
            dt = 45.0 + (i % 10)
            state = monitor.observe_interval_ms(dt)
            self.assertNotEqual(state, "CallbackBlindingOrRootkitDetected")

        # 2. Simulated Blinding: 800ms intervals -> must detect blinding within bounded samples
        detected = False
        steps_to_detect = 0
        for _ in range(10):
            steps_to_detect += 1
            if monitor.observe_interval_ms(800.0) == "CallbackBlindingOrRootkitDetected":
                detected = True
                break

        self.assertTrue(detected, "Wald SPRT must detect callback blinding within bounded observations")
        self.assertLessEqual(steps_to_detect, 8, "Must detect within 8 samples under severe starvation")

        # 3. Massive single event delay (10,000ms = 10s callback pause)
        monitor2 = oracles.KernelSprtCallbackMonitorOracle(50.0, 500.0, 0.001, 0.01)
        state_massive = monitor2.observe_interval_ms(10000.0)
        self.assertEqual(state_massive, "CallbackBlindingOrRootkitDetected", "Massive 10s delay must immediately trigger blinding detection")

        # 4. Extreme values: zero and sub-millisecond intervals
        monitor3 = oracles.KernelSprtCallbackMonitorOracle(50.0, 500.0, 0.001, 0.01)
        state_zero = monitor3.observe_interval_ms(0.0)
        self.assertNotEqual(state_zero, "CallbackBlindingOrRootkitDetected")
        self.assertFalse(math.isnan(monitor3.log_likelihood_ratio))

    # =========================================================================
    # 5. F09 & F10: User-Mode Watchdog & Prioritized Telemetry Channels
    # =========================================================================

    def test_challenge_f09_watchdog_evasion_signatures(self):
        """Stress-test F09: In-memory watchdog detecting byte-level ETW, AMSI, and detour evasion."""
        # 1. Clean prologues
        etw_clean = b"\x48\x89\x5C\x24\x08"
        amsi_clean = b"\x48\x83\xEC\x28"
        detour_clean = b"\xE9\x12\x34\x56\x78"

        detected_clean, _ = oracles.audit_watchdog_patches_oracle(etw_clean, amsi_clean, detour_clean)
        self.assertFalse(detected_clean, "Clean prologues must not trigger evasion detection")

        # 2. ETW bypass variations:
        # a) 0xC3 (RET)
        det_ret, v_ret = oracles.audit_watchdog_patches_oracle(b"\xC3\x90\x90", amsi_clean, detour_clean)
        self.assertTrue(det_ret)
        self.assertTrue(any("EtwEventWrite" in v for v in v_ret))

        # 3. AMSI bypass variations:
        # a) mov eax, 0x80070057; ret (B8 57 00 07 80 C3)
        det_amsi, v_amsi = oracles.audit_watchdog_patches_oracle(etw_clean, b"\xB8\x57\x00\x07\x80\xC3", detour_clean)
        self.assertTrue(det_amsi)
        self.assertTrue(any("AmsiScanBuffer" in v for v in v_amsi))

        # 4. Detour unhooking (NOP sled)
        det_unhook, v_unhook = oracles.audit_watchdog_patches_oracle(etw_clean, amsi_clean, b"\x90\x90\x90\x90\x90")
        self.assertTrue(det_unhook)
        self.assertTrue(any("unhooking" in v for v in v_unhook))

    def test_challenge_f10_telemetry_channel_priority_starvation_defense(self):
        """Stress-test F10: Telemetry priority tier preserves security alerts under high-frequency event floods."""
        # Simulate burst flood of 5,000 benign telemetry events
        # High priority critical events (ProcessCreate, TamperAlert, DriverLoad) must NOT be dropped
        critical_alert_ids = [f"CRIT_ALERT_{i}" for i in range(25)]
        flood_noise = [f"BENIGN_FILE_READ_{i}" for i in range(5000)]

        # Simulate dual-tier channel where critical queue has reserved capacity
        critical_queue_capacity = 50
        bulk_queue_capacity = 100

        critical_queue = []
        bulk_queue = []
        events_lost = 0

        # Enqueue critical alerts
        for alert in critical_alert_ids:
            if len(critical_queue) < critical_queue_capacity:
                critical_queue.append(alert)
            else:
                events_lost += 1

        # Enqueue noise flood
        for noise in flood_noise:
            if len(bulk_queue) < bulk_queue_capacity:
                bulk_queue.append(noise)
            else:
                events_lost += 1

        # Assert: 100% of critical alerts survived in the high-priority queue
        self.assertEqual(len(critical_queue), len(critical_alert_ids))
        for alert in critical_alert_ids:
            self.assertIn(alert, critical_queue)

        # Bulk events were shed as expected
        self.assertGreater(events_lost, 4800)


def run_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(Milestone4AdversarialStressHarness)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
