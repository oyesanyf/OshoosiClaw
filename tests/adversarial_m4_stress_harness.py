"""
tests/adversarial_m4_stress_harness.py

Milestone 4 Independent Adversarial Challenge & Empirical Stress Test Harness
Conducted by teamwork_challenger_m4_r2_2 (Empirical Challenger).

Target Features:
- F09: User-Mode In-Memory Hook, Detour Integrity, ETW & AMSI Tamper Watchdog
- F10: Prioritized Dual-Tier Telemetry Channels, Flood Defense & TELEMETRY_EVENTS_LOST Counter
- F11: Ring-0 Bring Your Own Vulnerable Driver (BYOVD) SHA-256 Blocklist
- F12: Periodic Kernel Callback Registration Self-Integrity Assertions
- F25: Hardware HVCI / VBS / VTL1 Posture Verifier (NtQuerySystemInformation 0x67)
- F26: Cross-View DKOM Process Differential & O(1) Wald SPRT Callback Sensor (H0 vs H1, Thresholds, Renewal Reset)
- F32: Continuous Distributed Attestation & TPM 2.0 PCR-Bound Heartbeat Ratchet
- F32: P2P Mesh Dead-Man's Switch Absence Quarantine Under Network Partition, Latency Spikes, and Clock Skew
- F32: Pre-Load Static Driver PE Analyzer Under Malformed Section Headers, Excessive Section Count, Circular Imports, and Zero-Byte Files
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
    # 1. F09 & F10: Watchdog, Detour Byte Integrity & Telemetry Prioritization
    # =========================================================================

    def test_challenge_f09_watchdog_detour_and_symbol_tamper_matrix(self):
        """Stress-test F09: In-memory watchdog byte-level inspection for ETW, AMSI, and detour evasion."""
        clean_etw = b"\x48\x89\x5C\x24\x08"       # mov [rsp+8], rbx
        clean_amsi = b"\x48\x83\xEC\x28"       # sub rsp, 28h
        clean_detour = b"\xE9\x12\x34\x56\x78" # jmp hook_target

        # 1. Clean benign function prologues must NEVER trigger false evasion detections
        detected, findings = oracles.audit_watchdog_patches_oracle(clean_etw, clean_amsi, clean_detour)
        self.assertFalse(detected, "Clean standard prologues must not trigger evasion detection")
        self.assertEqual(len(findings), 0)

        # 2. Exhaustive ETW bypass patch permutations (matching inspect_prologue_for_evasion):
        etw_patches = [
            (b"\xC3\x90\x90\x90", "ret (0xC3)"),
            (b"\xC2\x14\x00\x90", "ret imm16 (0xC2 0x14 0x00)"),
            (b"\x33\xC0\xC3\x90", "xor eax,eax; ret (33 C0 C3)"),
            (b"\x31\xC0\xC3\x90", "xor eax,eax; ret (31 C0 C3)"),
            (b"\x48\x33\xC0\xC3", "xor rax,rax; ret (48 33 C0 C3)"),
            (b"\x48\x31\xC0\xC3", "xor rax,rax; ret (48 31 C0 C3)"),
            (b"\xB8\x00\x00\x00\x00\xC3", "mov eax, 0; ret"),
        ]
        for patch_bytes, desc in etw_patches:
            det, f = oracles.audit_watchdog_patches_oracle(patch_bytes, clean_amsi, clean_detour)
            self.assertTrue(det, f"ETW bypass patch {desc} must be detected")
            self.assertTrue(any("EtwEventWrite" in item for item in f), f"Must identify EtwEventWrite for {desc}")

        # 3. Exhaustive AMSI bypass patch permutations:
        amsi_patches = [
            (b"\xC3\x90\x90\x90", "ret (0xC3)"),
            (b"\xB8\x57\x00\x07\x80\xC3", "mov eax, 0x80070057; ret (B8 57 00 07 80 C3)"),
            (b"\xB8\x57\x00\x07\x80\x90", "mov eax, 0x80070057 (B8 57 00 07 80)"),
            (b"\x31\xC0\xC3\x90", "xor eax,eax; ret (31 C0 C3)"),
            (b"\x33\xC0\xC3\x90", "xor eax,eax; ret (33 C0 C3)"),
        ]
        for patch_bytes, desc in amsi_patches:
            det, f = oracles.audit_watchdog_patches_oracle(clean_etw, patch_bytes, clean_detour)
            self.assertTrue(det, f"AMSI bypass patch {desc} must be detected")
            self.assertTrue(any("AmsiScanBuffer" in item for item in f), f"Must identify AmsiScanBuffer for {desc}")

        # 4. Detour trampoline unhooking attacks:
        # a) NOP sled unhooking
        det_nop, f_nop = oracles.audit_watchdog_patches_oracle(clean_etw, clean_amsi, b"\x90\x90\x90\x90\x90")
        self.assertTrue(det_nop, "NOP sled detour unhooking must be detected")
        self.assertTrue(any("NOP-sled" in item for item in f_nop))

        # b) INT3 debugger / breakpoint wipe
        det_int3, f_int3 = oracles.audit_watchdog_patches_oracle(clean_etw, clean_amsi, b"\xCC\xCC\xCC\xCC\xCC")
        self.assertTrue(det_int3, "INT3 wipe detour unhooking must be detected")

        # 5. Boundary cases: empty slices and truncated 1-byte / 2-byte inputs
        det_empty, _ = oracles.audit_watchdog_patches_oracle(b"", b"", b"")
        self.assertFalse(det_empty, "Empty slices must not trigger panics or false alarms")

        det_1byte, _ = oracles.audit_watchdog_patches_oracle(b"\x48", b"\x48", b"\x48")
        self.assertFalse(det_1byte, "Incomplete single prefix byte must not trigger false alarms")

    def test_challenge_f10_dual_tier_telemetry_prioritization_and_loss_counting(self):
        """Stress-test F10: Dual-tier telemetry channels prioritize security alerts under high-volume flood and track TELEMETRY_EVENTS_LOST."""
        # Synthesize an event stream:
        # 10,000 noisy bulk events (stat, file read, network poll)
        # Interspersed with 90 critical security events (process injection, driver load, tamper alert)
        bulk_events = [
            {"event_id": 2, "data": {"Hook": "FileRead", "Path": f"C:\\workspace\\file_{i}.tmp"}}
            for i in range(10000)
        ]

        critical_events = [
            {"event_id": 1, "data": {"Hook": "CreateProcessW", "Exe": "cmd.exe"}},
            {"event_id": 6, "data": {"Hook": "DriverLoad", "Path": "C:\\drivers\\test.sys"}},
            {"event_id": 8, "data": {"Hook": "CreateRemoteThread", "TargetPid": 1234}},
            {"event_id": 10, "data": {"Hook": "ProcessAccess", "DesiredAccess": 0x1F0FFF}},
            {"event_id": 4688, "data": {"Hook": "ProcessCreateAudit", "Pid": 4444}},
            {"event_id": 7045, "data": {"Hook": "ServiceInstalled", "ServiceName": "OsoosiSvc"}},
            {"event_id": 999, "data": {"Hook": "TelemetryTamperingDetected", "CriticalPriority": True}},
            {"event_id": 999, "data": {"Hook": "NtAllocateVirtualMemory", "CriticalPriority": True}},
            {"event_id": 999, "data": {"Hook": "NtProtectVirtualMemory", "CriticalPriority": True}},
        ]
        all_critical = critical_events * 10
        self.assertEqual(len(all_critical), 90)

        # Interleave: 1 critical event every 100 bulk events
        stream = []
        c_idx = 0
        for i, b in enumerate(bulk_events):
            stream.append(b)
            if i % 100 == 0 and c_idx < len(all_critical):
                stream.append(all_critical[c_idx])
                c_idx += 1

        while c_idx < len(all_critical):
            stream.append(all_critical[c_idx])
            c_idx += 1

        # Channel limits: Critical queue = 100, Bulk queue = 500
        tx_crit, tx_bulk, events_lost = oracles.dispatch_prioritized_telemetry_oracle(
            events=stream,
            critical_capacity=100,
            bulk_capacity=500,
        )

        # 1. 100% of critical security events must survive in tx_critical with 0 loss
        self.assertEqual(len(tx_crit), 90, "All 90 critical events must be routed to tx_critical")
        for ev in tx_crit:
            is_c = oracles.is_critical_telemetry_event_oracle(ev.get("event_id", 0), ev.get("data", {}))
            self.assertTrue(is_c, "All events in tx_critical must be genuinely classified as critical")

        # 2. Bulk queue capacity capped at exactly 500
        self.assertEqual(len(tx_bulk), 500, "Bulk queue must be filled to capacity (500)")

        # 3. TELEMETRY_EVENTS_LOST must accurately count all dropped bulk events
        expected_lost = len(bulk_events) - 500  # 10,000 - 500 = 9,500
        self.assertEqual(events_lost, expected_lost, f"TELEMETRY_EVENTS_LOST must be exactly {expected_lost}")

    # =========================================================================
    # 2. F32: Dead-Man's Switch, Network Partition, Latency & Clock Skew
    # =========================================================================

    def test_challenge_f32_dead_man_switch_network_partition_and_clock_skew(self):
        """Stress-test F32: Dead-man's switch absence quarantine under network partition, latency spikes, and clock skew."""
        switch = oracles.P2pMeshDeadMansSwitchOracle(heartbeat_interval_ms=1000, max_tolerance_intervals=3)
        self.assertEqual(switch.evaluate_dead_man_switch(self.now), "Nominal")

        genesis = oracles.TpmPcrHeartbeatRatchetOracle(epoch=1, pcr_digest=self.genesis_pcr, timestamp_utc=self.now)
        switch.ingest_heartbeat(genesis, self.now)
        self.assertEqual(switch.evaluate_dead_man_switch(self.now), "Nominal")

        # 1. Network partition simulation: no heartbeats arrive for 10 seconds
        # t = now + 1: within interval (elapsed 1000ms <= 1000ms) -> Nominal
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 1), "Nominal")

        # t = now + 2: missed 1 interval (elapsed 2000ms) -> WarningStaleHeartbeat
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 2), "WarningStaleHeartbeat")

        # t = now + 3: missed 2 intervals (elapsed 3000ms == timeout_ms) -> WarningStaleHeartbeat
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 3), "WarningStaleHeartbeat")

        # t = now + 4: absence timeout expired (elapsed 4000ms > 3000ms) -> AbsenceQuarantineDeadManTriggered
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 4), "AbsenceQuarantineDeadManTriggered")

        # t = now + 10: partition ongoing -> stays AbsenceQuarantineDeadManTriggered
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 10), "AbsenceQuarantineDeadManTriggered")

        # 2. Network partition heals: valid sequential heartbeat arrives (epoch 2)
        step2 = genesis.advance(nonce=b"heal_nonce", state_digest=hashlib.sha256(b"state2").digest(), timestamp_utc=self.now + 11)
        res_heal = switch.ingest_heartbeat(step2, self.now + 11)
        self.assertEqual(res_heal, "Nominal")
        self.assertEqual(switch.evaluate_dead_man_switch(self.now + 11), "Nominal")

        # 3. Out-of-order delayed packet arriving from network partition (epoch 1 re-delivered)
        res_delayed = switch.ingest_heartbeat(genesis, self.now + 12)
        self.assertEqual(res_delayed, "CryptographicRatchetTamperDetected")

        # 4. Backward clock skew (e.g. NTP backwards step or VM pause):
        # Current time steps backwards to now - 50s: saturating_sub ensures elapsed_secs = 0
        status_backwards = switch.evaluate_dead_man_switch(self.now - 50)
        self.assertNotEqual(
            status_backwards,
            "AbsenceQuarantineDeadManTriggered",
            "Backward clock skew must not trigger false positive absence quarantine",
        )

        # 5. Extreme forward clock skew / latency spike:
        # Advance with timestamp in the past relative to genesis -> ValueError
        with self.assertRaises(ValueError):
            genesis.advance(nonce=b"nonce", state_digest=hashlib.sha256(b"s").digest(), timestamp_utc=self.now - 1)

    # =========================================================================
    # 3. F32: Pre-Load Driver PE Analyzer Under Corrupt / Malformed Inputs
    # =========================================================================

    def test_challenge_f32_driver_pe_malformed_sections_and_circular_imports(self):
        """Stress-test F32: Pre-load driver PE analyzer under malformed section headers, excessive sections, circular imports, and zero bytes."""
        clean_pe = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00" + b"\x00" * 0x40 + b"PE\x00\x00" + b"CleanDriverContent"

        # 1. Zero-byte file: must execute safely without index out of bounds or panic
        v_zero, vuln_zero, r_zero = oracles.analyze_driver_pe_oracle(b"", "zero.sys")
        self.assertEqual(v_zero, "Permit")
        self.assertFalse(vuln_zero)
        self.assertEqual(len(r_zero), 0)

        # 2. Corrupt e_lfanew pointers:
        # a) e_lfanew = 0xFFFFFFFF (points far past file length)
        pe_bad_lfanew = b"MZ" + b"\x00" * 0x3A + b"\xFF\xFF\xFF\xFF" + b"\x00" * 100
        v_bad_lfanew, vuln_bad_lfanew, _ = oracles.analyze_driver_pe_oracle(pe_bad_lfanew, "bad_lfanew.sys")
        self.assertEqual(v_bad_lfanew, "Permit")
        self.assertFalse(vuln_bad_lfanew)

        # b) e_lfanew = 0x00000000 (points to DOS signature MZ instead of PE\0\0)
        pe_zero_lfanew = b"MZ" + b"\x00" * 0x3A + b"\x00\x00\x00\x00" + b"\x00" * 100
        v_zero_lfanew, vuln_zero_lfanew, _ = oracles.analyze_driver_pe_oracle(pe_zero_lfanew, "zero_lfanew.sys")
        self.assertEqual(v_zero_lfanew, "Permit")
        self.assertFalse(vuln_zero_lfanew)

        # 3. Excessive section count (NumberOfSections = 65535 / 0xFFFF)
        # PE header layout: PE\0\0 (4b) + Machine (2b) + NumberOfSections (2b)
        excessive_sections_pe = (
            b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00"
            + b"PE\x00\x00"
            + b"\x64\x86"  # Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)
            + b"\xFF\xFF"  # NumberOfSections = 65535
            + b"\x00" * 128
        )
        v_excess, vuln_excess, _ = oracles.analyze_driver_pe_oracle(excessive_sections_pe, "excessive_sections.sys")
        self.assertEqual(v_excess, "Permit")
        self.assertFalse(vuln_excess)

        # 4. Corrupted section headers (PointerToRawData = 0xFFFFFFFF, VirtualSize = 0)
        # Embedded with dangerous sink (MmMapIoSpace) in the payload
        corrupted_section_pe = (
            excessive_sections_pe
            + b".text\x00\x00\x00"
            + b"\x00\x00\x00\x00"  # VirtualSize = 0
            + b"\x00\x10\x00\x00"  # VirtualAddress
            + b"\x00\x10\x00\x00"  # SizeOfRawData
            + b"\xFF\xFF\xFF\xFF"  # PointerToRawData = 0xFFFFFFFF (corrupt)
            + b"\x00" * 16
            + b"ArbitrarySinkBytes: MmMapIoSpace\x00"
        )
        v_corrupt, vuln_corrupt, r_corrupt = oracles.analyze_driver_pe_oracle(corrupted_section_pe, "corrupt_sec.sys")
        self.assertEqual(v_corrupt, "QuarantineBlockByovd")
        self.assertTrue(vuln_corrupt)
        self.assertTrue(any("MmMapIoSpace" in r for r in r_corrupt))

        # 5. Circular imports / forwarder loop:
        # Import table descriptor referencing circular relative virtual addresses
        circular_import_pe = (
            clean_pe
            + b"\x00IMAGE_IMPORT_DESCRIPTOR\x00"
            + b"\x10\x00\x00\x00"  # OriginalFirstThunk -> points to offset A
            + b"\x00\x00\x00\x00"  # TimeDateStamp
            + b"\x10\x00\x00\x00"  # ForwarderChain -> circular loop
            + b"\x00" * 32
            + b"DangerousImport: ZwMapViewOfSection\x00"
        )
        v_circ, vuln_circ, r_circ = oracles.analyze_driver_pe_oracle(circular_import_pe, "circular.sys")
        self.assertEqual(v_circ, "QuarantineBlockByovd")
        self.assertTrue(vuln_circ)
        self.assertTrue(any("ZwMapViewOfSection" in r for r in r_circ))

        # 6. Direct WRMSR instruction in corrupt PE (0x0F 0x30)
        msr_corrupt = corrupted_section_pe + b"\x0F\x30\xC3"
        v_msr_c, vuln_msr_c, r_msr_c = oracles.analyze_driver_pe_oracle(msr_corrupt, "msr_corrupt.sys")
        self.assertEqual(v_msr_c, "QuarantineBlockByovd")
        self.assertTrue(vuln_msr_c)
        self.assertTrue(any("WRMSR" in r for r in r_msr_c))

    # =========================================================================
    # 4. F26: Wald SPRT Sensor Boundary Conditions (H0 vs H1, Reset, Invariants)
    # =========================================================================

    def test_challenge_f26_wald_sprt_sensor_h0_h1_boundaries_and_reset(self):
        """Stress-test F26: Wald SPRT sensor boundary conditions (H0 nominal vs H1 attack, renewal reset, numerical stability)."""
        # Monitor configuration: expected nominal = 50ms, anomaly = 500ms, alpha = 0.001, beta = 0.01
        alpha = 0.001
        beta = 0.01
        expected_interval = 50.0
        anomaly_interval = 500.0

        monitor = oracles.KernelSprtCallbackMonitorOracle(
            expected_interval_ms=expected_interval,
            anomaly_interval_ms=anomaly_interval,
            alpha=alpha,
            beta=beta,
        )

        # 1. Zero-sample boundary condition:
        # Before observing any samples, cumulative log-likelihood ratio S_0 must be exactly 0.0
        self.assertEqual(monitor.log_likelihood_ratio, 0.0)
        self.assertLess(monitor.lower_threshold_a, 0.0)
        self.assertGreater(monitor.upper_threshold_b, 0.0)

        # Theoretical thresholds:
        # a = ln(beta / (1 - alpha)) = ln(0.01 / 0.999) ~= -4.604
        # b = ln((1 - beta) / alpha) = ln(0.99 / 0.001) ~= +6.898
        self.assertAlmostEqual(monitor.lower_threshold_a, math.log(beta / (1.0 - alpha)), places=4)
        self.assertAlmostEqual(monitor.upper_threshold_b, math.log((1.0 - beta) / alpha), places=4)

        # 2. H0 (Nominal Hypothesis) Convergence & Renewal Reset:
        # Feed nominal samples (50.0ms).
        # Step LLR = ln(lambda1/lambda0) + (lambda0 - lambda1) * 50
        # = ln(0.002 / 0.02) + (0.02 - 0.002) * 50 = ln(0.1) + 0.018 * 50 = -2.3026 + 0.9 = -1.4026 < 0
        # After ~4 nominal steps, S_n crosses lower_threshold_a (-4.604).
        # The sensor must trigger renewal reset: S_n resets to 0.0 and returns "Nominal"!
        reset_occurred = False
        for step in range(1, 15):
            st = monitor.observe_interval_ms(50.0)
            if st == "Nominal":
                reset_occurred = True
                self.assertEqual(monitor.log_likelihood_ratio, 0.0, "S_n must be reset to 0.0 on lower threshold crossing")

        self.assertTrue(reset_occurred, "Wald SPRT must achieve H0 renewal reset on consecutive nominal samples")

        # 3. H1 (Attack Hypothesis / Blinding) Convergence:
        # Sudden callback starvation (800ms intervals).
        # Step LLR = ln(0.1) + 0.018 * 800 = -2.3026 + 14.4 = +12.0974 > 0
        # In a single step or two, S_n crosses upper_threshold_b (+6.898)
        st_blinding = monitor.observe_interval_ms(800.0)
        self.assertEqual(
            st_blinding,
            "CallbackBlindingOrRootkitDetected",
            "Severe 800ms callback delay must cross upper threshold and detect blinding",
        )

        # 4. Indifference Region Alternation (Oscillation):
        # Fresh monitor: alternate between 50ms and 140ms
        monitor_osc = oracles.KernelSprtCallbackMonitorOracle(50.0, 500.0, 0.001, 0.01)
        for _ in range(10):
            st1 = monitor_osc.observe_interval_ms(50.0)
            self.assertNotEqual(st1, "CallbackBlindingOrRootkitDetected")
            st2 = monitor_osc.observe_interval_ms(140.0)
            self.assertNotEqual(st2, "CallbackBlindingOrRootkitDetected")

        # 5. Numerical stability & extreme values:
        # a) dt = 0.0 ms -> clamped to 0.1ms, does not produce -inf or NaN
        m_num = oracles.KernelSprtCallbackMonitorOracle(50.0, 500.0, 0.001, 0.01)
        st_zero = m_num.observe_interval_ms(0.0)
        self.assertFalse(math.isnan(m_num.log_likelihood_ratio))
        self.assertFalse(math.isinf(m_num.log_likelihood_ratio))

        # b) dt = 1e9 ms (massive multi-year pause) -> cleanly triggers blinding
        st_huge = m_num.observe_interval_ms(1e9)
        self.assertEqual(st_huge, "CallbackBlindingOrRootkitDetected")
        self.assertFalse(math.isnan(m_num.log_likelihood_ratio))

    # =========================================================================
    # 5. F11, F12 & F25: BYOVD, Callback Self-Integrity & Hardware HVCI
    # =========================================================================

    def test_challenge_f11_byovd_hash_blocklist_all_ten_drivers(self):
        """Stress-test F11: Verify all 10 known BYOVD driver Authenticode SHA-256 hashes are blocked regardless of renamed files."""
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

            # 3. Mutated 1-char hash: must NOT block
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

        # 3. Pseudo-PIDs (PID 0 Idle, PID 4 System) must never trigger false positives
        handles_sys = [0, 4]
        detected_sys, hidden_sys, _ = oracles.detect_cross_view_dkom_discrepancy_oracle([], handles_sys)
        self.assertFalse(detected_sys)
        self.assertEqual(len(hidden_sys), 0)


def run_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(Milestone4AdversarialStressHarness)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
