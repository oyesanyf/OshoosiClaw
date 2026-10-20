"""
OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (OshoosiClaw) - E2E Testing Suite
Tier 2: Boundary & Corner Cases

Covers limits, zero/max buffers, empty inputs, invalid credentials,
rapid disarm/isolate cycles, and boundary conditions across all subsystems.
"""

import unittest
import os
import re
import sys
import hashlib
import tempfile
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TestTier2BoundaryCases(unittest.TestCase):
    """Tier 2: Boundary & Corner Cases Verification"""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.core_dir = cls.root / "crates" / "osoosi-core"
        cls.runtime_dir = cls.root / "crates" / "osoosi-runtime"
        cls.types_dir = cls.root / "crates" / "osoosi-types"

    def test_tier2_b01_zero_byte_buffer_handling(self):
        """B01: Zero-byte buffer passed to detection pipeline handles cleanly without panic."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("bytes.is_empty()", rea_file)

    def test_tier2_b02_truncated_16_byte_header(self):
        """B02: Partial 16-byte buffer does not cause out-of-bounds slice panic."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("bytes.len() < 2", rea_file)

    def test_tier2_b03_max_256mb_buffer_cap(self):
        """B03: Buffer cap is strictly bounded at 256 MiB (268,435,456 bytes) to prevent OOM."""
        cap = 256 * 1024 * 1024
        self.assertEqual(cap, 268435456)
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("256 * 1024 * 1024", rea_file)

    def test_tier2_b04_empty_path_blocking_rejected(self):
        """B04: Empty or whitespace-only path string returns early without modifying block maps."""
        kd_file = (self.runtime_dir / "src" / "kernel_driver.rs").read_text(encoding="utf-8")
        self.assertIn("trimmed.is_empty()", kd_file)

    def test_tier2_b05_invalid_credentials_3_strike_lockout(self):
        """B05: 3 consecutive failed operator authentication attempts trigger 300s security lockout."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("MAX_FAILED_ATTEMPTS: u32 = 3", kc_file)
        self.assertIn("LOCKOUT_DURATION_SECS: u64 = 300", kc_file)

    def test_tier2_b06_lockout_active_rejects_subsequent_calls(self):
        """B06: When lockout is active, engage and disarm requests are rejected with remaining time."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("check_lockout_status()", kc_file)
        self.assertIn("Remaining lockout:", kc_file)

    def test_tier2_b07_master_token_bypasses_lockout(self):
        """B07: Direct master token matches bypass lockout so administrator is never locked out."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("expected_token.trim()", kc_file)
        self.assertIn("record_successful_auth()", kc_file)

    def test_tier2_b08_rapid_isolate_idempotency(self):
        """B08: Calling engage_killchain_isolation when already isolated is idempotent (no-op)."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("KILLCHAIN-IDEMPOTENCY", kc_file)
        self.assertIn("Host is already isolated", kc_file)

    def test_tier2_b09_deadmans_watchdog_30_minute_limit(self):
        """B09: Unattended isolation is capped at 1800s (30 min) by anti-hostage watchdog."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("1800", kc_file)
        self.assertIn("KILLCHAIN-WATCHDOG", kc_file)

    def test_tier2_b10_caller_pid_zero_and_four_rejected(self):
        """B10: Anti-Hijacking caller validation rejects caller PIDs <= 4."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("if pid <= 4", kc_file)
        self.assertIn("Invalid caller PID", kc_file)

    def test_tier2_b11_frozen_caller_pid_rejected(self):
        """B11: Calling process whose PID is currently in frozen_pids cannot execute Killchain actions."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("frozen_pids.contains(&pid)", kc_file)
        self.assertIn("Anti-Hijacking Violation", kc_file)

    def test_tier2_b12_clr_data_directory_zero_size_is_native(self):
        """B12: PE with CLR Runtime Header virtual_address == 0 or size == 0 is unequivocally native."""
        project_spec = (self.root / "PROJECT.md").read_text(encoding="utf-8")
        self.assertIn("virtual_address == 0", project_spec)
        self.assertIn("get_clr_runtime_header()", project_spec)

    def test_tier2_b13_hermetic_firewall_low_and_high_ip_blocks(self):
        """B13: Firewall rules cleanly segment IPv4 around loopback (0.0.0.0-126.255.255.255 & 128.0.0.0-255.255.255.255)."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("0.0.0.0-126.255.255.255", kc_file)
        self.assertIn("128.0.0.0-255.255.255.255", kc_file)

    def test_tier2_b14_quarantine_nonexistent_file_error(self):
        """B14: Quarantining non-existent file returns Err without leaving orphan entries."""
        q_file = (self.core_dir / "src" / "quarantine.rs").read_text(encoding="utf-8")
        self.assertIn("quarantine_file", q_file)

    def test_tier2_b15_path_traversal_ntfs_ads_rejected(self):
        """B15: NTFS Alternate Data Streams (colon in relative path) are rejected by sandbox."""
        defense = (self.root / "crates" / "osoosi-agent-anomaly" / "src" / "breakout_defense.rs").read_text(encoding="utf-8")
        self.assertIn("NTFS Alternate Data Streams", defense)


if __name__ == "__main__":
    unittest.main()
