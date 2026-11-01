"""
Milestone 4 Challenger 2 Empirical Stress Test Harness
Target: Machine Binding Quorum & Drift Tolerance, Dynamic Master Signing Key Loading (M20)
"""

import os
import sys
import json
import hashlib
import tempfile
import unittest
import subprocess
from pathlib import Path

# Try to import blake3 if available, else use hashlib/fallback
try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False


def compute_blake3_hash(data: bytes) -> str:
    if HAS_BLAKE3:
        return blake3.blake3(data).hexdigest()
    # Fallback simulation if blake3 python package is missing
    return hashlib.sha256(b"BLAKE3_SIM:" + data).hexdigest()


def compute_blake3_keyed(key: bytes, data: bytes) -> bytes:
    if HAS_BLAKE3:
        return blake3.blake3(data, key=key).digest()
    return hashlib.sha256(key + b":BLAKE3_KEYED:" + data).digest()


class MachineBindingOracles:
    """Independent mathematical and algorithmic verification oracles for machine binding."""

    @staticmethod
    def hash_mac(mac_formatted: str) -> str:
        key = f"OSHOOSI_MAC_ANCHOR_V1:{mac_formatted}"
        return compute_blake3_hash(key.encode("utf-8"))

    @staticmethod
    def hash_os_machine_id(machine_id: str) -> str:
        key = f"OSHOOSI_OS_MACHINE_ID_ANCHOR_V1:{machine_id}"
        return compute_blake3_hash(key.encode("utf-8"))

    @staticmethod
    def hash_silicon_anchor(silicon: str) -> str:
        key = f"OSHOOSI_SILICON_ANCHOR_V1:{silicon}"
        return compute_blake3_hash(key.encode("utf-8"))

    @staticmethod
    def evaluate_quorum(manifest: dict, live_macs: list, live_os_hash: str,
                        live_silicon_hash: str, live_seal_hash: str) -> tuple:
        """
        Oracle evaluating the 4-anchor machine binding quorum and MAC drift adaptation.
        Returns (is_bound, verdict, non_mac_matches, historical_len).
        """
        # Count non-MAC anchor matches (0 to 3)
        non_mac_matches = 0
        if manifest.get("os_machine_id_hash") == live_os_hash:
            non_mac_matches += 1
        if manifest.get("silicon_anchor_hash") == live_silicon_hash:
            non_mac_matches += 1
        if manifest.get("local_seal_hash") == live_seal_hash:
            non_mac_matches += 1

        # Check MAC match against enrolled or historical
        enrolled = set(manifest.get("enrolled_physical_mac_hashes", []))
        historical = set(manifest.get("historical_mac_hashes", []))
        mac_matched = any(h in enrolled or h in historical for h in live_macs)

        # Quorum rule: Fail closed if non_mac_matches < 2
        if non_mac_matches < 2:
            return (False, f"ForeignHostDetected: Only {non_mac_matches} of 3 immutable anchors matched", non_mac_matches, len(historical))

        if mac_matched:
            return (True, "BOUND", non_mac_matches, len(historical))

        # Legitimate MAC rotation adaptation
        # Add old enrolled to historical ring (capped at 16)
        hist_list = list(manifest.get("historical_mac_hashes", []))
        for old_h in manifest.get("enrolled_physical_mac_hashes", []):
            if old_h not in hist_list:
                hist_list.append(old_h)
        while len(hist_list) > 16:
            hist_list.pop(0)

        return (True, "MAC_ROTATION_ADAPTED", non_mac_matches, len(hist_list))


class DynamicKeyLoaderOracle:
    """Independent oracle for dynamic master signing key resolution (M20)."""

    @staticmethod
    def resolve_key(env_var: str = None, key_files: list = None,
                    is_debug_or_test: bool = True) -> tuple:
        """
        Resolves 32-byte master key according to M20 precedence rules:
        1. Environment variable `OSOOSI_SIGNING_PRIVATE_KEY_HEX`
        2. External key files (raw binary 32B or 64-char hex)
        3. Ephemeral fallback (in test/debug mode)
        4. Error (in release mode when unconfigured)
        """
        # 1. Environment variable
        if env_var is not None:
            trimmed = env_var.strip()
            if len(trimmed) == 64:
                try:
                    b = bytes.fromhex(trimmed)
                    if len(b) == 32:
                        return (True, b, "ENV_VAR")
                except ValueError:
                    pass

        # 2. Candidate key files
        if key_files:
            for f_path in key_files:
                p = Path(f_path)
                if p.exists() and p.is_file():
                    content = p.read_bytes()
                    if len(content) == 32:
                        return (True, content, "FILE_BINARY")
                    try:
                        text = content.decode("utf-8").strip()
                        if len(text) == 64:
                            b = bytes.fromhex(text)
                            if len(b) == 32:
                                return (True, b, "FILE_HEX")
                    except Exception:
                        pass

        # 3. Fallback for test/debug
        if is_debug_or_test:
            fallback = compute_blake3_hash(b"OSHOOSI_EPHEMERAL_DEV_MASTER_KEY")
            return (True, bytes.fromhex(fallback)[:32], "FALLBACK_TEST")

        return (False, None, "ERROR_UNCONFIGURED")


class TestChallengerM4EmpiricalSuite(unittest.TestCase):
    """Empirical test cases executed by Challenger 2."""

    def test_oracle_quorum_rejection_on_foreign_host(self):
        """Stress-test 2-of-3 and 3-of-3 non-MAC anchor tampering permutations."""
        live_os = "valid_os_hash_1111"
        live_silicon = "valid_silicon_hash_2222"
        live_seal = "valid_seal_hash_3333"
        live_macs = ["valid_mac_hash_aaaa"]

        manifest_base = {
            "os_machine_id_hash": live_os,
            "silicon_anchor_hash": live_silicon,
            "local_seal_hash": live_seal,
            "enrolled_physical_mac_hashes": live_macs,
            "historical_mac_hashes": [],
        }

        # Case 1: Benign baseline -> BOUND
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            manifest_base, live_macs, live_os, live_silicon, live_seal
        )
        self.assertTrue(ok)
        self.assertEqual(verdict, "BOUND")
        self.assertEqual(matches, 3)

        # Case 2: Tamper OS + Silicon (1/3 match) -> FAIL
        m_tamper_1 = dict(manifest_base)
        m_tamper_1["os_machine_id_hash"] = "foreign_os"
        m_tamper_1["silicon_anchor_hash"] = "foreign_silicon"
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_tamper_1, live_macs, live_os, live_silicon, live_seal
        )
        self.assertFalse(ok)
        self.assertIn("ForeignHostDetected", verdict)
        self.assertEqual(matches, 1)

        # Case 3: Tamper OS + Seal (1/3 match) -> FAIL
        m_tamper_2 = dict(manifest_base)
        m_tamper_2["os_machine_id_hash"] = "foreign_os"
        m_tamper_2["local_seal_hash"] = "foreign_seal"
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_tamper_2, live_macs, live_os, live_silicon, live_seal
        )
        self.assertFalse(ok)
        self.assertIn("ForeignHostDetected", verdict)
        self.assertEqual(matches, 1)

        # Case 4: Tamper Silicon + Seal (1/3 match) -> FAIL
        m_tamper_3 = dict(manifest_base)
        m_tamper_3["silicon_anchor_hash"] = "foreign_silicon"
        m_tamper_3["local_seal_hash"] = "foreign_seal"
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_tamper_3, live_macs, live_os, live_silicon, live_seal
        )
        self.assertFalse(ok)
        self.assertIn("ForeignHostDetected", verdict)
        self.assertEqual(matches, 1)

        # Case 5: Tamper All 3 (0/3 match) -> FAIL
        m_tamper_4 = dict(manifest_base)
        m_tamper_4["os_machine_id_hash"] = "foreign_os"
        m_tamper_4["silicon_anchor_hash"] = "foreign_silicon"
        m_tamper_4["local_seal_hash"] = "foreign_seal"
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_tamper_4, live_macs, live_os, live_silicon, live_seal
        )
        self.assertFalse(ok)
        self.assertIn("ForeignHostDetected", verdict)
        self.assertEqual(matches, 0)

        # Case 6: Cloned Manifest + MAC Spoofing (MAC matches, but OS+Silicon differ) -> MUST FAIL
        m_cloned = dict(manifest_base)
        m_cloned["os_machine_id_hash"] = "rogue_os_id"
        m_cloned["silicon_anchor_hash"] = "rogue_cpu"
        # Enrolled MAC matches the live MAC!
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_cloned, live_macs, live_os, live_silicon, live_seal
        )
        self.assertFalse(ok, "MAC match MUST NOT bypass non-MAC quorum failure!")
        self.assertIn("ForeignHostDetected", verdict)

    def test_oracle_drift_tolerance_single_anchor_change(self):
        """Verify that 2-of-3 non-MAC anchor match succeeds (legitimate hardware/OS upgrade)."""
        live_os = "valid_os_hash_1111"
        live_silicon = "valid_silicon_hash_2222"
        live_seal = "valid_seal_hash_3333"
        live_macs = ["valid_mac_hash_aaaa"]

        manifest_base = {
            "os_machine_id_hash": live_os,
            "silicon_anchor_hash": live_silicon,
            "local_seal_hash": live_seal,
            "enrolled_physical_mac_hashes": live_macs,
            "historical_mac_hashes": [],
        }

        # 1. CPU upgrade (silicon changes, OS and seal match) -> 2/3 matches
        m_cpu = dict(manifest_base)
        m_cpu["silicon_anchor_hash"] = "old_cpu_silicon"
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_cpu, live_macs, live_os, live_silicon, live_seal
        )
        self.assertTrue(ok)
        self.assertEqual(verdict, "BOUND")
        self.assertEqual(matches, 2)

        # 2. OS reinstall (OS changes, silicon and seal match) -> 2/3 matches
        m_os = dict(manifest_base)
        m_os["os_machine_id_hash"] = "old_os_guid"
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_os, live_macs, live_os, live_silicon, live_seal
        )
        self.assertTrue(ok)
        self.assertEqual(verdict, "BOUND")
        self.assertEqual(matches, 2)

        # 3. Seal re-generation (seal changes, OS and silicon match) -> 2/3 matches
        m_seal = dict(manifest_base)
        m_seal["local_seal_hash"] = "old_seal_hash"
        ok, verdict, matches, _ = MachineBindingOracles.evaluate_quorum(
            m_seal, live_macs, live_os, live_silicon, live_seal
        )
        self.assertTrue(ok)
        self.assertEqual(verdict, "BOUND")
        self.assertEqual(matches, 2)

    def test_oracle_mac_rotation_adaptation_and_16_entry_ring_buffer_cap(self):
        """Stress-test 50 successive MAC rotations, verifying ring buffer stays <= 16."""
        live_os = "valid_os_hash"
        live_silicon = "valid_silicon_hash"
        live_seal = "valid_seal_hash"

        current_manifest = {
            "os_machine_id_hash": live_os,
            "silicon_anchor_hash": live_silicon,
            "local_seal_hash": live_seal,
            "enrolled_physical_mac_hashes": ["mac_initial_00"],
            "historical_mac_hashes": [],
        }

        for cycle in range(1, 51):
            new_live_mac = [f"mac_cycle_{cycle:03d}"]
            ok, verdict, matches, hist_len = MachineBindingOracles.evaluate_quorum(
                current_manifest, new_live_mac, live_os, live_silicon, live_seal
            )
            self.assertTrue(ok)
            self.assertEqual(verdict, "MAC_ROTATION_ADAPTED")
            self.assertLessEqual(hist_len, 16, f"Cycle {cycle}: Historical ring buffer exceeded 16 entries!")

            # Update manifest state as would happen in verify_and_adapt_machine_binding
            hist = list(current_manifest["historical_mac_hashes"])
            for m in current_manifest["enrolled_physical_mac_hashes"]:
                if m not in hist:
                    hist.append(m)
            while len(hist) > 16:
                hist.pop(0)

            current_manifest["enrolled_physical_mac_hashes"] = new_live_mac
            current_manifest["historical_mac_hashes"] = hist

        # Final check: ring length must be exactly 16
        self.assertEqual(len(current_manifest["historical_mac_hashes"]), 16)
        # Most recent enrolled must be mac_cycle_050
        self.assertEqual(current_manifest["enrolled_physical_mac_hashes"], ["mac_cycle_050"])
        # Oldest in historical ring must be mac_cycle_034 (50 - 16)
        self.assertEqual(current_manifest["historical_mac_hashes"][0], "mac_cycle_034")

    def test_dynamic_key_loader_priority_and_edge_cases(self):
        """Verify M20 Dynamic Master Signing Key Loading priority and parsing edge cases."""
        # 1. Valid 64-char hex in environment variable
        valid_hex = "0123456789abcdef" * 4
        ok, key, src = DynamicKeyLoaderOracle.resolve_key(env_var=valid_hex)
        self.assertTrue(ok)
        self.assertEqual(src, "ENV_VAR")
        self.assertEqual(key.hex(), valid_hex)

        # 2. Invalid hex lengths in environment variable fall through
        for invalid_len_hex in ["0123456789abcdef" * 3 + "123", "0123456789abcdef" * 4 + "99"]:
            ok, key, src = DynamicKeyLoaderOracle.resolve_key(env_var=invalid_len_hex, is_debug_or_test=True)
            self.assertTrue(ok)
            self.assertEqual(src, "FALLBACK_TEST", f"Invalid length {len(invalid_len_hex)} should fall through")

        # 3. Invalid non-hex characters fall through
        invalid_chars = "zzzzzzzz" + ("0123456789abcdef" * 3) + "12345678"
        self.assertEqual(len(invalid_chars), 64)
        ok, key, src = DynamicKeyLoaderOracle.resolve_key(env_var=invalid_chars, is_debug_or_test=True)
        self.assertTrue(ok)
        self.assertEqual(src, "FALLBACK_TEST")

        # 4. Key file loading with temporary files
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Raw binary 32-byte file
            bin_file = tmp_path / "signing.key"
            raw_bytes = os.urandom(32)
            bin_file.write_bytes(raw_bytes)

            ok, key, src = DynamicKeyLoaderOracle.resolve_key(env_var=None, key_files=[str(bin_file)])
            self.assertTrue(ok)
            self.assertEqual(src, "FILE_BINARY")
            self.assertEqual(key, raw_bytes)

            # Hex text 64-char file
            hex_file = tmp_path / "signing_hex.key"
            hex_text = os.urandom(32).hex()
            hex_file.write_text(hex_text + "\n")

            ok, key, src = DynamicKeyLoaderOracle.resolve_key(env_var=None, key_files=[str(hex_file)])
            self.assertTrue(ok)
            self.assertEqual(src, "FILE_HEX")
            self.assertEqual(key.hex(), hex_text)

            # 5. Precedence: Environment variable beats key file
            ok, key, src = DynamicKeyLoaderOracle.resolve_key(
                env_var=valid_hex, key_files=[str(bin_file)]
            )
            self.assertTrue(ok)
            self.assertEqual(src, "ENV_VAR")
            self.assertEqual(key.hex(), valid_hex)

        # 6. Release mode without configuration returns error
        ok, key, src = DynamicKeyLoaderOracle.resolve_key(
            env_var=None, key_files=[], is_debug_or_test=False
        )
        self.assertFalse(ok)
        self.assertEqual(src, "ERROR_UNCONFIGURED")


if __name__ == "__main__":
    unittest.main()
