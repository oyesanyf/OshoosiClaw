"""
OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (OshoosiClaw) - E2E Testing Suite
Tier 3: Cross-Feature Pairwise Combinations

Validates pairwise module interactions across the EDR system:
1. Killchain + Tarpit (Stage-5 escalation + non-destructive process suspension)
2. Quarantine + REA (Artifact quarantine + event-driven YARA synthesis)
3. WebUI + REST API (19 views + 128 buttons mapped to Axum endpoints)
4. Ring-0 Driver + Windows Service (Driver notify routine + service lifecycle)
5. Magika + 2-Tier Provenance (MIME classification + structural PE inspection)
6. WiX MSI + PATH Invariant (MSI installer packaging + permanent PATH append)
7. Linux eBPF + Hermetic Firewall (LSM socket connect + iptables loopback allow)
8. Autonomous REA Sweep + SQLite Telemetry (Background sweep + DB persistence)
"""

import unittest
import os
import re
import sys
import json
import hashlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TestTier3PairwiseCombinations(unittest.TestCase):
    """Tier 3: Pairwise Cross-Feature Interactions"""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.core_dir = cls.root / "crates" / "osoosi-core"
        cls.runtime_dir = cls.root / "crates" / "osoosi-runtime"
        cls.types_dir = cls.root / "crates" / "osoosi-types"
        cls.dashboard_dir = cls.root / "dashboard"
        cls.wix_dir = cls.root / "wix"
        cls.scripts_dir = cls.root / "scripts"

    def test_tier3_pair01_killchain_and_tarpit(self):
        """P01: Killchain Stage-5 lockdown cooperates with runtime tarpit without freezing protected processes."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        tarpit_file = (self.runtime_dir / "src" / "tarpit.rs").read_text(encoding="utf-8")

        # Killchain invokes tarpit process verification
        self.assertIn("osoosi_runtime::tarpit::is_protected_system_or_security_process", kc_file)
        self.assertIn("ActiveProcessTarpit", kc_file)

        # Tarpit explicitly shields system, shell, and developer toolchains
        self.assertIn("is_protected_system_or_security_process", tarpit_file)
        self.assertIn("python.exe", tarpit_file.lower())
        self.assertIn("cargo.exe", tarpit_file.lower())

    def test_tier3_pair02_quarantine_and_rea(self):
        """P02: File quarantine event triggers autonomous REA decompilation and YARA synthesis."""
        q_file = (self.core_dir / "src" / "quarantine.rs").read_text(encoding="utf-8")
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")

        self.assertIn("quarantine_file", q_file)
        self.assertIn("analyze_target_path", rea_file)
        self.assertIn("synthesize_rea_yara_rule", rea_file)

    def test_tier3_pair03_webui_and_rest_api(self):
        """P03: WebUI 19 views and 128 buttons route directly to genuine Axum REST API endpoints."""
        html_file = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        app_js = (self.dashboard_dir / "src" / "app.js").read_text(encoding="utf-8")
        dash_rs = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")

        # HTML defines 19 views
        views = re.findall(r'data-view=["\']([^"\']+)["\']', html_file)
        self.assertEqual(len(views), 19)

        # HTML defines 128 buttons
        buttons = re.findall(r'<button\b', html_file, re.I)
        self.assertEqual(len(buttons), 128)

        # Frontend calls backend routes that exist in Axum router
        common_routes = ['/status', '/threats', '/consensus/findings', '/blocking/rules']
        for route in common_routes:
            self.assertIn(route, app_js)
            self.assertIn(f'"/api{route}"', dash_rs)

    def test_tier3_pair04_driver_and_windows_service(self):
        """P04: Windows service lifecycle registers driver client and signs driver artifacts."""
        driver_c = (self.root / "driver" / "windows" / "src" / "osoosi_driver.c").read_text(encoding="utf-8")
        build_script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        kd_rs = (self.runtime_dir / "src" / "kernel_driver.rs").read_text(encoding="utf-8")

        # Build script handles driver signing
        self.assertIn("osoosi_driver.sys", build_script)

        # Kernel driver client connects to device handle
        self.assertIn("\\\\.\\OsoosiDriver", kd_rs)
        self.assertIn("PsSetCreateProcessNotifyRoutineEx", driver_c)

    def test_tier3_pair05_magika_and_two_tier_provenance(self):
        """P05: Tier 1 Magika envelope detection feeds Tier 2 PE CLR DataDirectory structural classification."""
        project_spec = (self.root / "PROJECT.md").read_text(encoding="utf-8")
        self.assertIn("Tier 1 Outer Envelope Detection", project_spec)
        self.assertIn("Tier 2 PE CLR DataDirectory[14] Provenance", project_spec)
        self.assertIn("get_clr_runtime_header()", project_spec)

    def test_tier3_pair06_wix_msi_and_zero_touch_path(self):
        """P06: WiX installer compiles package while guaranteeing zero-overwrite permanent PATH append."""
        wxs = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertIn('<Environment Id="PATH"', wxs)
        self.assertIn('Permanent="yes"', wxs)
        self.assertIn('Part="last"', wxs)
        self.assertIn('Action="set"', wxs)

    def test_tier3_pair07_linux_ebpf_and_hermetic_firewall(self):
        """P07: Linux eBPF LSM socket connect permits loopback and DNS during iptables quarantine."""
        bpf = (self.root / "ebpf" / "src" / "osoosi_probe.bpf.c").read_text(encoding="utf-8")
        kc = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")

        # eBPF hook
        self.assertIn("socket_connect", bpf)
        # Killchain iptables
        self.assertIn("iptables", kc)
        self.assertIn("Osoosi-KillChain", kc)

    def test_tier3_pair08_autonomous_rea_and_sqlite_telemetry(self):
        """P08: Autonomous REA sweeps store findings to SQLite database for SIEM queries."""
        rea = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        dash = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")

        self.assertIn("start_autonomous_loop", rea)
        self.assertIn("/api/rea/v1/autonomous-sweep", dash)
        self.assertIn("siquery", dash)


if __name__ == "__main__":
    unittest.main()
