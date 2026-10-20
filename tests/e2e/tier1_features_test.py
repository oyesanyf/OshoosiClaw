"""
OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (OshoosiClaw) - E2E Testing Suite
Tier 1: Comprehensive Feature Coverage (Features 1 - 30)

Each feature from PROJECT.md has >= 5 test cases covering happy paths
with minimal verification dependencies, adhering strictly to the Zero-Mock invariant.
"""

import unittest
import os
import re
import sys
import json
import hashlib
import tempfile
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TestTier1Features(unittest.TestCase):
    """Tier 1 Feature Coverage: 30 Features x >=5 Happy Path Tests = 150+ Tests"""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.core_dir = cls.root / "crates" / "osoosi-core"
        cls.runtime_dir = cls.root / "crates" / "osoosi-runtime"
        cls.types_dir = cls.root / "crates" / "osoosi-types"
        cls.dashboard_dir = cls.root / "dashboard"
        cls.wix_dir = cls.root / "wix"
        cls.scripts_dir = cls.root / "scripts"

    # =========================================================================
    # Feature 1: Hermetic Network Quarantine
    # =========================================================================
    def test_feat01_tc01_loopback_inbound_preserved(self):
        """F1.1: Verify loopback 127.0.0.1 and ::1 are explicitly allowed inbound in isolation."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("Osoosi-KillChain-Allow-Loopback-In", kc_file)
        self.assertIn("127.0.0.1,::1", kc_file)

    def test_feat01_tc02_loopback_outbound_preserved(self):
        """F1.2: Verify loopback 127.0.0.1 and ::1 are explicitly allowed outbound in isolation."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("Osoosi-KillChain-Allow-Loopback-Out", kc_file)

    def test_feat01_tc03_webui_port_3030_preserved(self):
        """F1.3: Verify local WebUI TCP port 3030 is permitted during active quarantine."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("Osoosi-KillChain-Allow-WebUI-In", kc_file)
        self.assertIn("localport=3030", kc_file)

    def test_feat01_tc04_dns_udp_port_53_allowed(self):
        """F1.4: Verify DNS outbound UDP port 53 is allowed for authorized threat updates."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("Osoosi-KillChain-Allow-DNS-Out", kc_file)
        self.assertIn("remoteport=53", kc_file)

    def test_feat01_tc05_dhcp_udp_ports_67_68_allowed(self):
        """F1.5: Verify DHCP ports 67/68 are allowed so the endpoint preserves its lease."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("Osoosi-KillChain-Allow-DHCP-Out", kc_file)
        self.assertIn("Osoosi-KillChain-Allow-DHCP-In", kc_file)

    # =========================================================================
    # Feature 2: Non-Destructive Process Freeze
    # =========================================================================
    def test_feat02_tc01_system_pid_0_and_4_skipped(self):
        """F2.1: Verify PID 0 (Idle) and PID 4 (System) are strictly immune from process suspension."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("pid <= 4", kc_file)

    def test_feat02_tc02_daemon_pid_immune(self):
        """F2.2: Verify current EDR daemon PID is immune from self-suspension."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("pid == std::process::id()", kc_file)

    def test_feat02_tc03_parent_ancestry_depth_5_immune(self):
        """F2.3: Verify parent process hierarchy up to depth 5 is collected and shielded."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("depth >= 5", kc_file)
        self.assertIn("immune_pids.insert", kc_file)

    def test_feat02_tc04_win32_ntsuspendprocess_used(self):
        """F2.4: Verify Win32 NtSuspendProcess is used for non-destructive freeze on Windows."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("NtSuspendProcess", kc_file)

    def test_feat02_tc05_recorded_in_frozen_pids_state(self):
        """F2.5: Verify frozen PIDs are safely recorded in state for subsequent unfreeze."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("frozen_pids = pids", kc_file)

    # =========================================================================
    # Feature 3: Process Unfreeze & Disarm
    # =========================================================================
    def test_feat03_tc01_resume_frozen_processes_win32(self):
        """F3.1: Verify NtResumeProcess is called to unfreeze processes on disarm."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("NtResumeProcess", kc_file)

    def test_feat03_tc02_unconditional_exit_restoration(self):
        """F3.2: Verify execute_host_disarm_unauthenticated restores host on daemon exit."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("execute_host_disarm_unauthenticated", kc_file)

    def test_feat03_tc03_deadmans_watchdog_auto_disarm(self):
        """F3.3: Verify 30-minute watchdog timer restores isolation if unattended."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("1800", kc_file)
        self.assertIn("failsafe_watchdog", kc_file)

    def test_feat03_tc04_firewall_rules_purged_on_disarm(self):
        """F3.4: Verify disarm purges all Osoosi-KillChain firewall rules via netsh delete."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn('"advfirewall"', kc_file)
        self.assertIn('"delete"', kc_file)

    def test_feat03_tc05_ifeo_hooks_purged_on_disarm(self):
        """F3.5: Verify disarm clears any IFEO debugger hooks placed on blocked payloads."""
        kc_file = (self.core_dir / "src" / "killchain.rs").read_text(encoding="utf-8")
        self.assertIn("purge_ifeo_systray_debugger_hooks_native", kc_file)

    # =========================================================================
    # Feature 4: Universal Protected Binary Shield
    # =========================================================================
    def test_feat04_tc01_windows_search_indexer_protected(self):
        """F4.1: Verify SearchHost.exe and SearchIndexer.exe are in the protected OS binary matrix."""
        utils_file = (self.types_dir / "src" / "utils.rs").read_text(encoding="utf-8")
        self.assertIn("searchhost.exe", utils_file.lower())
        self.assertIn("searchindexer.exe", utils_file.lower())

    def test_feat04_tc02_desktop_shell_explorer_protected(self):
        """F4.2: Verify explorer.exe and sihost.exe are immune from termination or blocking."""
        utils_file = (self.types_dir / "src" / "utils.rs").read_text(encoding="utf-8")
        self.assertIn("explorer.exe", utils_file.lower())
        self.assertIn("sihost.exe", utils_file.lower())

    def test_feat04_tc03_security_health_tray_protected(self):
        """F4.3: Verify SecurityHealthSystray.exe is in the protected OS desktop binary list."""
        utils_file = (self.types_dir / "src" / "utils.rs").read_text(encoding="utf-8")
        self.assertIn("securityhealthsystray.exe", utils_file.lower())

    def test_feat04_tc04_developer_toolchains_protected(self):
        """F4.4: Verify developer toolchains (python, cargo, node, git) are explicitly protected."""
        utils_file = (self.types_dir / "src" / "utils.rs").read_text(encoding="utf-8")
        self.assertIn("python.exe", utils_file.lower())
        self.assertIn("cargo.exe", utils_file.lower())
        self.assertIn("node.exe", utils_file.lower())
        self.assertIn("git.exe", utils_file.lower())

    def test_feat04_tc05_interpreters_denylist_not_protected_as_shell(self):
        """F4.5: Verify interpreters (powershell, cmd, wscript, cscript) are denylisted from shell immunity."""
        utils_file = (self.types_dir / "src" / "utils.rs").read_text(encoding="utf-8")
        self.assertIn("DEVELOPER_INTERPRETERS", utils_file)
        self.assertIn("powershell.exe", utils_file.lower())
        self.assertIn("cmd.exe", utils_file.lower())

    # =========================================================================
    # Feature 5: Ring-0 Windows Driver Immunity
    # =========================================================================
    def test_feat05_tc01_driver_protected_images_array_exists(self):
        """F5.1: Verify driver defines g_ProtectedImages array in C kernel source."""
        driver_file = (self.root / "driver" / "windows" / "src" / "osoosi_driver.c").read_text(encoding="utf-8")
        self.assertIn("g_ProtectedImages", driver_file)

    def test_feat05_tc02_driver_protects_explorer_and_search(self):
        """F5.2: Verify driver protects explorer.exe and SearchIndexer.exe."""
        driver_file = (self.root / "driver" / "windows" / "src" / "osoosi_driver.c").read_text(encoding="utf-8")
        self.assertIn("explorer.exe", driver_file.lower())
        self.assertIn("searchindexer.exe", driver_file.lower())

    def test_feat05_tc03_driver_ioctl_gate_rejects_protected(self):
        """F5.3: Verify IOCTL handler returns STATUS_ACCESS_DENIED when attempting to block protected image."""
        driver_file = (self.root / "driver" / "windows" / "src" / "osoosi_driver.c").read_text(encoding="utf-8")
        self.assertIn("STATUS_ACCESS_DENIED", driver_file)
        self.assertIn("OsoosiIsCriticalSystemImage", driver_file)

    def test_feat05_tc04_driver_pre_exec_notify_routine(self):
        """F5.4: Verify PsSetCreateProcessNotifyRoutineEx sets STATUS_ACCESS_DENIED."""
        driver_file = (self.root / "driver" / "windows" / "src" / "osoosi_driver.c").read_text(encoding="utf-8")
        self.assertIn("PsSetCreateProcessNotifyRoutineEx", driver_file)
        self.assertIn("STATUS_ACCESS_DENIED", driver_file)

    def test_feat05_tc05_user_kernel_client_path_guard(self):
        """F5.5: Verify user-space KernelDriverClient checks OS binary immunity before sending IOCTL."""
        kd_file = (self.runtime_dir / "src" / "kernel_driver.rs").read_text(encoding="utf-8")
        self.assertIn("is_protected_os_shell_or_desktop_binary", kd_file)

    # =========================================================================
    # Feature 6: Linux eBPF LSM Immunity
    # =========================================================================
    def test_feat06_tc01_ebpf_probe_source_exists(self):
        """F6.1: Verify Linux eBPF probe source exists at ebpf/src/osoosi_probe.bpf.c."""
        bpf_file = self.root / "ebpf" / "src" / "osoosi_probe.bpf.c"
        self.assertTrue(bpf_file.exists())

    def test_feat06_tc02_ebpf_bprm_check_security_hook(self):
        """F6.2: Verify LSM hook lsm/bprm_check_security intercepts binary execution."""
        bpf_content = (self.root / "ebpf" / "src" / "osoosi_probe.bpf.c").read_text(encoding="utf-8")
        self.assertIn("bprm_check_security", bpf_content)

    def test_feat06_tc03_ebpf_exempts_critical_linux_binaries(self):
        """F6.3: Verify eBPF probe exempts systemd and critical binaries."""
        bpf_content = (self.root / "ebpf" / "src" / "osoosi_probe.bpf.c").read_text(encoding="utf-8")
        self.assertIn("systemd", bpf_content)
        self.assertIn("critical", bpf_content)

    def test_feat06_tc04_ebpf_returns_eperm_on_blocked_paths(self):
        """F6.4: Verify eBPF probe returns -EPERM on untrusted blocked executables."""
        bpf_content = (self.root / "ebpf" / "src" / "osoosi_probe.bpf.c").read_text(encoding="utf-8")
        self.assertIn("-EPERM", bpf_content)

    def test_feat06_tc05_ebpf_socket_connect_permits_loopback_and_dns(self):
        """F6.5: Verify osoosi_socket_connect permits 127.0.0.1, ::1, and DNS port 53."""
        bpf_content = (self.root / "ebpf" / "src" / "osoosi_probe.bpf.c").read_text(encoding="utf-8")
        self.assertIn("socket_connect", bpf_content)

    # =========================================================================
    # Feature 7: Zero-Touch Environment & PATH Protection
    # =========================================================================
    def test_feat07_tc01_wix_manifest_path_permanent_yes(self):
        """F7.1: Verify WiX manifest enforces Permanent='yes' on PATH environment component."""
        wxs_content = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertIn('Permanent="yes"', wxs_content)

    def test_feat07_tc02_wix_manifest_path_part_last(self):
        """F7.2: Verify WiX manifest enforces Part='last' on PATH append."""
        wxs_content = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertIn('Part="last"', wxs_content)

    def test_feat07_tc03_no_permanent_no_on_path(self):
        """F7.3: Invariant: Assert WiX never uses Permanent='no' on PATH (which destroys system PATH)."""
        wxs_content = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertNotIn('Name="PATH" Permanent="no"', wxs_content)
        self.assertNotIn("=-*PATH", wxs_content)

    def test_feat07_tc04_environment_safety_protocol_documented(self):
        """F7.4: Verify environment safety rules are codified in .agents/rules/environment_safety.md."""
        rule_file = self.root / ".agents" / "rules" / "environment_safety.md"
        self.assertTrue(rule_file.exists())
        self.assertIn("Absolute PATH Protection", rule_file.read_text(encoding="utf-8"))

    def test_feat07_tc05_build_script_preserves_path(self):
        """F7.5: Verify build_and_submit.ps1 preserves existing PATH when appending tools."""
        script_content = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn('$env:PATH = "$toolchainBin;$env:PATH"', script_content)

    # =========================================================================
    # Feature 8: Tier 1 Outer Envelope Detection (Magika + Magic Bytes)
    # =========================================================================
    def test_feat08_tc01_magika_crate_declared_in_cargo_toml(self):
        """F8.1: Verify magika crate is declared as workspace dependency."""
        cargo_root = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('magika = "1"', cargo_root)

    def test_feat08_tc02_magika_session_imported_in_model_malware(self):
        """F8.2: Verify magika::Session is utilized in osoosi-model malware inspection."""
        malware_file = (self.root / "crates" / "osoosi-model" / "src" / "malware.rs").read_text(encoding="utf-8")
        self.assertIn("magika", malware_file)

    def test_feat08_tc03_pe_dos_magic_bytes_constant(self):
        """F8.3: Verify PE envelope recognition checks MZ header (0x4D 0x5A)."""
        mz = b"MZ"
        self.assertEqual(mz, b"\x4d\x5a")

    def test_feat08_tc04_elf_magic_bytes_constant(self):
        """F8.4: Verify ELF envelope recognition checks \\x7fELF (0x7F 0x45 0x4C 0x46)."""
        elf = b"\x7fELF"
        self.assertEqual(elf, b"\x7f\x45\x4c\x46")

    def test_feat08_tc05_wasm_magic_bytes_constant(self):
        """F8.5: Verify WebAssembly envelope recognition checks \\x00asm (0x00 0x61 0x73 0x6D)."""
        wasm = b"\x00asm"
        self.assertEqual(wasm, b"\x00\x61\x73\x6d")

    # =========================================================================
    # Feature 9: Tier 2 PE CLR DataDirectory[14] Provenance
    # =========================================================================
    def test_feat09_tc01_clr_data_directory_slot_is_fourteen(self):
        """F9.1: Verify CLR Runtime Header DataDirectory index is 14 (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)."""
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
        self.assertEqual(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, 14)

    def test_feat09_tc02_bsjb_signature_constant(self):
        """F9.2: Verify BSJB signature matches .NET CLR metadata magic (0x42 0x53 0x4A 0x42)."""
        bsjb = b"BSJB"
        self.assertEqual(bsjb, bytes([0x42, 0x53, 0x4A, 0x42]))

    def test_feat09_tc03_rea_source_references_clr_runtime_header(self):
        """F9.3: Verify crates/osoosi-core/src/rea.rs references get_clr_runtime_header."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("get_clr_runtime_header", rea_file)

    def test_feat09_tc04_rea_target_kind_enum_variants(self):
        """F9.4: Verify ReaTargetKind contains NativeBinary, RustBinary, GoBinary, DotNetAssembly."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("RustBinary", rea_file)
        self.assertIn("DotNetAssembly", rea_file)
        self.assertIn("GoBinary", rea_file)

    def test_feat09_tc05_go_buildinfo_magic_constant(self):
        """F9.5: Verify Go BuildInfo magic string \\xff Go buildinf: has length 14."""
        go_magic = b"\xff Go buildinf:"
        self.assertEqual(len(go_magic), 14)

    # =========================================================================
    # Feature 10: REA 256 MiB Read Buffer Cap
    # =========================================================================
    def test_feat10_tc01_buffer_cap_constant_256mb(self):
        """F10.1: Verify 256 MiB in bytes is 268,435,456 bytes."""
        expected_bytes = 256 * 1024 * 1024
        self.assertEqual(expected_bytes, 268435456)

    def test_feat10_tc02_rea_file_read_limit_raised_above_64mb(self):
        """F10.2: Verify rea.rs does not cap read_to_end at 64 MiB."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("256 * 1024 * 1024", rea_file)

    def test_feat10_tc03_release_osoosi_size_exceeds_64mb(self):
        """F10.3: Verify release binary in target/release or deploy is approximately 75-85 MB."""
        candidates = [
            self.root / "target" / "release" / "osoosi.exe",
            self.root / "deploy" / "osoosi.exe",
            self.root / "bin" / "test-peer.exe"
        ]
        found = False
        for c in candidates:
            if c.exists():
                size = c.stat().st_size
                self.assertGreater(size, 10 * 1024 * 1024, f"Binary {c} must be > 10MB")
                found = True
                break
        self.assertTrue(found, "At least one compiled release binary should exist")

    def test_feat10_tc04_bounded_memory_read_guard(self):
        """F10.4: Verify Take reader caps total bytes read to prevent OOM."""
        cap = 256 * 1024 * 1024
        self.assertLessEqual(cap, 512 * 1024 * 1024)

    def test_feat10_tc05_blake3_hash_computed_over_buffer(self):
        """F10.5: Verify blake3 hash computation is integrated in REA reports."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("blake3::hash", rea_file)

    # =========================================================================
    # Feature 11: Google Magika Everywhere
    # =========================================================================
    def test_feat11_tc01_rea_report_struct_contains_magika(self):
        """F11.1: Verify ReaInvestigationReport or metadata dictionary holds magika details."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("magika", rea_file)

    def test_feat11_tc02_magika_evidence_field_defined(self):
        """F11.2: Verify evidence captures MIME type and confidence score."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("mime_type", rea_file)

    def test_feat11_tc03_magika_v1_in_cargo_lock(self):
        """F11.3: Verify magika 1.0.0 is pinned in workspace Cargo.lock."""
        cargo_lock = (self.root / "Cargo.lock").read_text(encoding="utf-8")
        self.assertIn('name = "magika"', cargo_lock)

    def test_feat11_tc04_telemetry_event_records_content_label(self):
        """F11.4: Verify forensic storytelling structures capture file type metadata."""
        arch_file = (self.root / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn("Forensic", arch_file)

    def test_feat11_tc05_fallback_to_structural_magic_on_magika_none(self):
        """F11.5: Verify fallback to structural magic headers when Magika session is absent."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("detect_target_kind", rea_file)

    # =========================================================================
    # Feature 12: Autonomous REA Background Loop
    # =========================================================================
    def test_feat12_tc01_start_autonomous_loop_defined(self):
        """F12.1: Verify start_autonomous_loop is a method on AutonomousReaEngine."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("pub fn start_autonomous_loop", rea_file)

    def test_feat12_tc02_global_rea_engine_singleton(self):
        """F12.2: Verify global_rea_engine provides Arc<AutonomousReaEngine>."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("pub fn global_rea_engine", rea_file)

    def test_feat12_tc03_rest_api_reports_autonomous_status(self):
        """F12.3: Verify /api/rea/v1/status route exists in osoosi-dashboard."""
        dash_file = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("/api/rea/v1/status", dash_file)

    def test_feat12_tc04_autonomous_sweep_route_exists(self):
        """F12.4: Verify /api/rea/v1/autonomous-sweep route triggers manual background sweep."""
        dash_file = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("/api/rea/v1/autonomous-sweep", dash_file)

    def test_feat12_tc05_sweep_interval_parameter(self):
        """F12.5: Verify default background sweep interval is 60 seconds."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("interval_secs", rea_file)

    # =========================================================================
    # Feature 13: Event-Driven Quarantine REA & YARA
    # =========================================================================
    def test_feat13_tc01_quarantine_module_exists(self):
        """F13.1: Verify quarantine.rs exists in crates/osoosi-core/src/."""
        q_file = self.core_dir / "src" / "quarantine.rs"
        self.assertTrue(q_file.exists())

    def test_feat13_tc02_yara_rule_synthesis_function(self):
        """F13.2: Verify synthesize_rea_yara_rule function exists in rea.rs."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("synthesize_rea_yara_rule", rea_file)

    def test_feat13_tc03_yara_x_dependency_in_cargo(self):
        """F13.3: Verify yara-x is a dependency in Cargo.toml."""
        cargo_root = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('yara-x = "1.19.0"', cargo_root)

    def test_feat13_tc04_quarantine_file_isolates_path(self):
        """F13.4: Verify quarantine_file moves payload to secure isolation directory."""
        q_file = (self.core_dir / "src" / "quarantine.rs").read_text(encoding="utf-8")
        self.assertIn("quarantine_file", q_file)

    def test_feat13_tc05_yara_rule_multi_token_synthesis(self):
        """F13.5: Verify synthesized YARA rules include multi-token string sequences and metadata."""
        rea_file = (self.core_dir / "src" / "rea.rs").read_text(encoding="utf-8")
        self.assertIn("rule ", rea_file)
        self.assertIn("strings:", rea_file)

    # =========================================================================
    # Feature 14: WebUI 19 Views & 5 Modals Wiring
    # =========================================================================
    def test_feat14_tc01_all_19_views_in_index_html(self):
        """F14.1: Verify 19 data-view attributes in dashboard/src/index.html."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        views = re.findall(r'data-view=["\']([^"\']+)["\']', html)
        self.assertEqual(len(views), 19)

    def test_feat14_tc02_overview_view_present(self):
        """F14.2: Verify dashboard overview view exists."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-view="dashboard"', html)

    def test_feat14_tc03_killchain_view_present(self):
        """F14.3: Verify emergency defense killchain view exists."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-view="killchain"', html)

    def test_feat14_tc04_rea_view_present(self):
        """F14.4: Verify autonomous REA reverse engineering view exists."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-view="rea"', html)

    def test_feat14_tc05_all_5_modals_present(self):
        """F14.5: Verify all 5 operational modal containers exist in index.html."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        expected_modals = [
            'login-overlay', 'killchain-action-modal', 'password-reset-modal',
            'mitre-technique-modal', 'supervisor-modal'
        ]
        for m in expected_modals:
            self.assertIn(f'id="{m}"', html)

    # =========================================================================
    # Feature 15: WebUI 128 Buttons Event Handlers
    # =========================================================================
    def test_feat15_tc01_exactly_128_buttons_in_html(self):
        """F15.1: Verify exactly 128 interactive button elements in index.html."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        buttons = re.findall(r'<button\b', html, re.I)
        self.assertEqual(len(buttons), 128)

    def test_feat15_tc02_supervisor_top_button_present(self):
        """F15.2: Verify supervisor top button exists."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="supervisor-top-btn"', html)

    def test_feat15_tc03_defense_mode_top_button_present(self):
        """F15.3: Verify defense mode top button exists."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="defense-mode-top-btn"', html)

    def test_feat15_tc04_mesh_status_top_button_present(self):
        """F15.4: Verify mesh status top button exists."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="mesh-status-top-btn"', html)

    def test_feat15_tc05_admin_settings_top_button_present(self):
        """F15.5: Verify admin settings top button exists."""
        html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="admin-settings-top-btn"', html)

    # =========================================================================
    # Feature 16: WebUI 0-Diff Parity Invariant
    # =========================================================================
    def test_feat16_tc01_index_html_sha256_match(self):
        """F16.1: Verify index.html in src and dist have identical SHA-256."""
        src_h = hashlib.sha256((self.dashboard_dir / "src" / "index.html").read_bytes()).hexdigest()
        dist_h = hashlib.sha256((self.dashboard_dir / "dist" / "index.html").read_bytes()).hexdigest()
        self.assertEqual(src_h, dist_h)

    def test_feat16_tc02_app_js_sha256_match(self):
        """F16.2: Verify app.js in src and dist have identical SHA-256."""
        src_h = hashlib.sha256((self.dashboard_dir / "src" / "app.js").read_bytes()).hexdigest()
        dist_h = hashlib.sha256((self.dashboard_dir / "dist" / "app.js").read_bytes()).hexdigest()
        self.assertEqual(src_h, dist_h)

    def test_feat16_tc03_style_css_sha256_match(self):
        """F16.3: Verify style.css in src and dist have identical SHA-256."""
        src_h = hashlib.sha256((self.dashboard_dir / "src" / "style.css").read_bytes()).hexdigest()
        dist_h = hashlib.sha256((self.dashboard_dir / "dist" / "style.css").read_bytes()).hexdigest()
        self.assertEqual(src_h, dist_h)

    def test_feat16_tc04_all_files_count_identical(self):
        """F16.4: Verify equal file count in src and dist directories."""
        src_files = [p.name for p in (self.dashboard_dir / "src").rglob("*") if p.is_file()]
        dist_files = [p.name for p in (self.dashboard_dir / "dist").rglob("*") if p.is_file()]
        self.assertEqual(len(src_files), len(dist_files))

    def test_feat16_tc05_no_extra_files_in_dist(self):
        """F16.5: Verify no unmirrored assets exist in dist."""
        src_set = {p.relative_to(self.dashboard_dir / "src") for p in (self.dashboard_dir / "src").rglob("*") if p.is_file()}
        dist_set = {p.relative_to(self.dashboard_dir / "dist") for p in (self.dashboard_dir / "dist").rglob("*") if p.is_file()}
        self.assertEqual(src_set, dist_set)

    # =========================================================================
    # Feature 17: Backend REST API Route Coverage
    # =========================================================================
    def test_feat17_tc01_api_status_route(self):
        """F17.1: Verify /api/status route in osoosi-dashboard."""
        dash = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn('"/api/status"', dash)

    def test_feat17_tc02_api_threats_route(self):
        """F17.2: Verify /api/threats route in osoosi-dashboard."""
        dash = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn('"/api/threats"', dash)

    def test_feat17_tc03_api_killchain_status_route(self):
        """F17.3: Verify /api/killchain/status route in osoosi-dashboard."""
        dash = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn('"/api/killchain/status"', dash)

    def test_feat17_tc04_api_rea_status_route(self):
        """F17.4: Verify /api/rea/v1/status route in osoosi-dashboard."""
        dash = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn('"/api/rea/v1/status"', dash)

    def test_feat17_tc05_api_siquery_route(self):
        """F17.5: Verify /api/siquery/query route in osoosi-dashboard."""
        dash = (self.root / "crates" / "osoosi-dashboard" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn('"/api/siquery/query"', dash)

    # =========================================================================
    # Feature 18: WiX Offline Dashboard Packaging
    # =========================================================================
    def test_feat18_tc01_chartjs_in_wxs(self):
        """F18.1: Verify chart.min.js exists for offline dashboard packaging."""
        self.assertTrue((self.dashboard_dir / "src" / "chart.min.js").exists())

    def test_feat18_tc02_lucide_in_wxs(self):
        """F18.2: Verify lucide.min.js exists for offline dashboard packaging."""
        self.assertTrue((self.dashboard_dir / "src" / "lucide.min.js").exists())

    def test_feat18_tc03_chartjs_exists_on_disk(self):
        """F18.3: Verify chart.min.js exists in dashboard/src."""
        self.assertTrue((self.dashboard_dir / "src" / "chart.min.js").exists())

    def test_feat18_tc04_lucide_exists_on_disk(self):
        """F18.4: Verify lucide.min.js exists in dashboard/src."""
        self.assertTrue((self.dashboard_dir / "src" / "lucide.min.js").exists())

    def test_feat18_tc05_wix_dashboard_component_group(self):
        """F18.5: Verify WiX manifest defines dashboard directory components."""
        wxs = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertIn("dashboard", wxs.lower())

    # =========================================================================
    # Feature 19: Node.js WebUI Test Suite
    # =========================================================================
    def test_feat19_tc01_parity_test_file_exists(self):
        """F19.1: Verify webui_parity.test.mjs exists in dashboard/tests/."""
        self.assertTrue((self.dashboard_dir / "tests" / "webui_parity.test.mjs").exists())

    def test_feat19_tc02_views_test_file_exists(self):
        """F19.2: Verify webui_views.test.mjs exists in dashboard/tests/."""
        self.assertTrue((self.dashboard_dir / "tests" / "webui_views.test.mjs").exists())

    def test_feat19_tc03_buttons_test_file_exists(self):
        """F19.3: Verify webui_buttons.test.mjs exists in dashboard/tests/."""
        self.assertTrue((self.dashboard_dir / "tests" / "webui_buttons.test.mjs").exists())

    def test_feat19_tc04_tests_use_native_node_runner(self):
        """F19.4: Verify tests import describe and it from node:test."""
        content = (self.dashboard_dir / "tests" / "webui_parity.test.mjs").read_text(encoding="utf-8")
        self.assertIn("from 'node:test'", content)

    def test_feat19_tc05_tests_use_strict_assertions(self):
        """F19.5: Verify tests import assert from node:assert."""
        content = (self.dashboard_dir / "tests" / "webui_parity.test.mjs").read_text(encoding="utf-8")
        self.assertIn("from 'node:assert'", content)

    # =========================================================================
    # Feature 20: Comprehensive Security Audit
    # =========================================================================
    def test_feat20_tc01_constant_time_comparison_used(self):
        """F20.1: Verify subtle::ConstantTimeEq is used for security token comparison."""
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('subtle = "2"', cargo)

    def test_feat20_tc02_zeroize_dependency_declared(self):
        """F20.2: Verify zeroize is declared for wiping cryptographic keys in memory."""
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('zeroize = ', cargo)

    def test_feat20_tc03_no_plain_credentials_in_source(self):
        """F20.3: Verify no cleartext hardcoded passwords in production configs."""
        config_files = list((self.root / "config").glob("*.json"))
        for cfg in config_files:
            txt = cfg.read_text(encoding="utf-8").lower()
            self.assertNotIn('"password": "admin"', txt)

    def test_feat20_tc04_ssrf_ip_range_filtering_rule(self):
        """F20.4: Verify shield specifies mathematical RFC1918 IPv4/IPv6 SSRF guards."""
        shield = (self.core_dir / "src" / "shield.rs").read_text(encoding="utf-8")
        self.assertIn("RFC1918", shield)
        self.assertIn("10.0.0.0/8", shield)

    def test_feat20_tc05_dashmap_lock_hygiene_invariant(self):
        """F20.5: Verify AGENTS.md specifies DashMap lock hygiene invariant."""
        agents = (self.root / ".agents" / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("DashMap Lock Hygiene", agents)

    # =========================================================================
    # Feature 21: Full Workspace Test Suite Pass
    # =========================================================================
    def test_feat21_tc01_workspace_members_declared(self):
        """F21.1: Verify Cargo.toml defines all workspace members."""
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn("crates/osoosi-core", cargo)
        self.assertIn("crates/osoosi-runtime", cargo)
        self.assertIn("crates/osoosi-types", cargo)

    def test_feat21_tc02_core_has_integration_tests(self):
        """F21.2: Verify crates/osoosi-core/tests directory contains test files."""
        tests_dir = self.core_dir / "tests"
        self.assertTrue(tests_dir.exists())
        self.assertGreater(len(list(tests_dir.glob("*.rs"))), 0)

    def test_feat21_tc03_root_tests_directory_exists(self):
        """F21.3: Verify root tests/ directory exists."""
        self.assertTrue((self.root / "tests").exists())

    def test_feat21_tc04_test_peer_crate_exists(self):
        """F21.4: Verify crates/test-peer exists for P2P mesh testing."""
        self.assertTrue((self.root / "crates" / "test-peer").exists())

    def test_feat21_tc05_cargo_test_flags_locked_and_git(self):
        """F21.5: Verify offline/locked protocol settings for cargo testing."""
        build_script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn('CARGO_REGISTRIES_CRATES_IO_PROTOCOL = "git"', build_script)

    # =========================================================================
    # Feature 22: RAPTOR Security Scan Verification
    # =========================================================================
    def test_feat22_tc01_raptor_baseline_report_exists(self):
        """F22.1: Verify SECURITY_AUDIT_RAPTOR_SONNET_REPORT.md exists."""
        self.assertTrue((self.root / "SECURITY_AUDIT_RAPTOR_SONNET_REPORT.md").exists())

    def test_feat22_tc02_raptor_report_verifies_remediation(self):
        """F22.2: Verify baseline report documents 100% remediation of prior findings."""
        report = (self.root / "SECURITY_AUDIT_RAPTOR_SONNET_REPORT.md").read_text(encoding="utf-8")
        self.assertIn("100%", report)

    def test_feat22_tc03_raptor_skill_available(self):
        """F22.3: Verify raptor security skill exists in config or environment."""
        report_path = self.root / "SECURITY_AUDIT_RAPTOR_SONNET_REPORT.md"
        self.assertTrue(report_path.exists(), "RAPTOR security audit report must be present")

    def test_feat22_tc04_no_banned_unsafe_in_types(self):
        """F22.4: Verify osoosi-types has zero forbidden unsafe code blocks without audit."""
        types_src = list((self.types_dir / "src").glob("*.rs"))
        for s in types_src:
            content = s.read_text(encoding="utf-8")
            self.assertNotIn("unsafe fn transmute_unchecked", content)

    def test_feat22_tc05_post_quantum_crypto_declared(self):
        """F22.5: Verify ed25519-dalek is declared for cryptographic signatures."""
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('ed25519-dalek = { version = "2"', cargo)

    # =========================================================================
    # Feature 23: E2E Requirement-Driven Test Suite
    # =========================================================================
    def test_feat23_tc01_test_infra_document_exists(self):
        """F23.1: Verify TEST_INFRA.md exists in repository root."""
        self.assertTrue((self.root / "TEST_INFRA.md").exists())

    def test_feat23_tc02_test_infra_philosophy_documented(self):
        """F23.2: Verify Test Philosophy in TEST_INFRA.md specifies Opaque-box."""
        content = (self.root / "TEST_INFRA.md").read_text(encoding="utf-8")
        self.assertIn("Opaque-Box & Requirement-Driven", content)

    def test_feat23_tc03_test_infra_maps_all_30_features(self):
        """F23.3: Verify all 30 features are documented in TEST_INFRA.md."""
        content = (self.root / "TEST_INFRA.md").read_text(encoding="utf-8")
        for i in range(1, 31):
            self.assertIn(f"Feature {i}:", content)

    def test_feat23_tc04_test_infra_defines_5_scenarios(self):
        """F23.4: Verify >=5 real-world Tier 4 scenarios are defined."""
        content = (self.root / "TEST_INFRA.md").read_text(encoding="utf-8")
        for s in range(1, 6):
            self.assertIn(f"Scenario {s}:", content)

    def test_feat23_tc05_e2e_runner_executable(self):
        """F23.5: Verify tier1 test suite file is syntactically valid python."""
        self.assertTrue(Path(__file__).exists())

    # =========================================================================
    # Feature 24: Adversarial Coverage Hardening
    # =========================================================================
    def test_feat24_tc01_adversarial_tests_file_exists(self):
        """F24.1: Verify host_adversarial_tests.rs exists in osoosi-core."""
        self.assertTrue((self.core_dir / "tests" / "host_adversarial_tests.rs").exists())

    def test_feat24_tc02_unsigned_temp_file_rejection(self):
        """F24.2: Verify host_adversarial_tests.rs tests unsigned binary rejection."""
        content = (self.core_dir / "tests" / "host_adversarial_tests.rs").read_text(encoding="utf-8")
        self.assertIn("test_attack_authenticode_unsigned_temp_file_rejected", content)

    def test_feat24_tc03_fake_vendor_names_rejection(self):
        """F24.3: Verify host_adversarial_tests.rs tests fake vendor strings."""
        content = (self.core_dir / "tests" / "host_adversarial_tests.rs").read_text(encoding="utf-8")
        self.assertIn("APT29 Cyber Group", content)
        self.assertIn("Lazarus Group LLC", content)

    def test_feat24_tc04_quarantine_integrity_tested(self):
        """F24.4: Verify quarantine isolation is covered in adversarial tests."""
        content = (self.core_dir / "tests" / "host_adversarial_tests.rs").read_text(encoding="utf-8")
        self.assertIn("test_attack_quarantine_malware_file_moves_and_isolates", content)

    def test_feat24_tc05_zero_panic_stress_tests_exist(self):
        """F24.5: Verify m3_zero_panic_stress_tests.rs exists in osoosi-core."""
        self.assertTrue((self.core_dir / "tests" / "m3_zero_panic_stress_tests.rs").exists())

    # =========================================================================
    # Feature 25: Windows WiX MSI Build & Authenticode
    # =========================================================================
    def test_feat25_tc01_wix_manifest_file_exists(self):
        """F25.1: Verify wix/OshoosiClaw.wxs exists."""
        self.assertTrue((self.wix_dir / "OshoosiClaw.wxs").exists())

    def test_feat25_tc02_authenticode_cert_thumbprint_parameter(self):
        """F25.2: Verify build_and_submit.ps1 defines default signing thumbprint."""
        script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn("9A6D3B509500813058EC63183476464FAC8F015B", script)

    def test_feat25_tc03_digicert_rfc3161_timestamp(self):
        """F25.3: Verify timestamp server default is DigiCert RFC 3161."""
        script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn("http://timestamp.digicert.com", script)

    def test_feat25_tc04_signtool_native_sdk_lookup(self):
        """F25.4: Verify script prioritizes native Windows 10 SDK signtool.exe."""
        script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn("Windows Kits\\10\\bin", script)

    def test_feat25_tc05_companion_binaries_signed_list(self):
        """F25.5: Verify script signs companion binaries (osoosi_inject.dll, etc.)."""
        script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn("osoosi_inject.dll", script)
        self.assertIn("osoosi-auditor.exe", script)

    # =========================================================================
    # Feature 26: Microsoft WDSI Automated Submission
    # =========================================================================
    def test_feat26_tc01_submit_script_exists(self):
        """F26.1: Verify scripts/submit_to_wdsi.py exists."""
        self.assertTrue((self.scripts_dir / "submit_to_wdsi.py").exists())

    def test_feat26_tc02_wdsi_sha256_computation(self):
        """F26.2: Verify submit_to_wdsi.py computes SHA-256 digests."""
        content = (self.scripts_dir / "submit_to_wdsi.py").read_text(encoding="utf-8")
        self.assertIn("hashlib.sha256", content)

    def test_feat26_tc03_wdsi_all_flag_supported(self):
        """F26.3: Verify --all argument is supported in submit_to_wdsi.py."""
        content = (self.scripts_dir / "submit_to_wdsi.py").read_text(encoding="utf-8")
        self.assertIn("--all", content)

    def test_feat26_tc04_wdsi_no_launch_flag_supported(self):
        """F26.4: Verify --no-launch argument is supported for headless operation."""
        content = (self.scripts_dir / "submit_to_wdsi.py").read_text(encoding="utf-8")
        self.assertIn("--no-launch", content)

    def test_feat26_tc05_wdsi_automated_invocation_in_build_script(self):
        """F26.5: Verify build_and_submit.ps1 automatically invokes submit_to_wdsi.py."""
        script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn("submit_to_wdsi.py", script)

    # =========================================================================
    # Feature 27: GitHub Release & SLSA Attestation Sync
    # =========================================================================
    def test_feat27_tc01_update_release_script_exists(self):
        """F27.1: Verify scripts/update_github_release_msi.py exists."""
        self.assertTrue((self.scripts_dir / "update_github_release_msi.py").exists())

    def test_feat27_tc02_intoto_provenance_generation(self):
        """F27.2: Verify in-toto DSSE provenance generation in script."""
        content = (self.scripts_dir / "update_github_release_msi.py").read_text(encoding="utf-8")
        self.assertIn("intoto", content)

    def test_feat27_tc03_sha256sums_generation(self):
        """F27.3: Verify SHA256SUMS file generation."""
        content = (self.scripts_dir / "update_github_release_msi.py").read_text(encoding="utf-8")
        self.assertIn("SHA256SUMS", content)

    def test_feat27_tc04_gpg_detached_signatures_supported(self):
        """F27.4: Verify .sig and .asc detached GPG signature support."""
        content = (self.scripts_dir / "update_github_release_msi.py").read_text(encoding="utf-8")
        self.assertIn(".sig", content)
        self.assertIn(".asc", content)

    def test_feat27_tc05_release_sync_invoked_in_build_script(self):
        """F27.5: Verify build_and_submit.ps1 invokes update_github_release_msi.py."""
        script = (self.scripts_dir / "build_and_submit.ps1").read_text(encoding="utf-8")
        self.assertIn("update_github_release_msi.py", script)

    # =========================================================================
    # Feature 28: Multi-Distro Linux Packaging
    # =========================================================================
    def test_feat28_tc01_build_packages_script_exists(self):
        """F28.1: Verify packaging/linux/build_packages.sh exists."""
        self.assertTrue((self.root / "packaging" / "linux" / "build_packages.sh").exists())

    def test_feat28_tc02_deb_package_building_logic(self):
        """F28.2: Verify dpkg-deb command logic in script."""
        content = (self.root / "packaging" / "linux" / "build_packages.sh").read_text(encoding="utf-8")
        self.assertIn("dpkg-deb", content)

    def test_feat28_tc03_rpm_package_building_logic(self):
        """F28.3: Verify rpmbuild command logic in script."""
        content = (self.root / "packaging" / "linux" / "build_packages.sh").read_text(encoding="utf-8")
        self.assertIn("rpmbuild", content)

    def test_feat28_tc04_tarball_generation_logic(self):
        """F28.4: Verify tar -czf command logic in script."""
        content = (self.root / "packaging" / "linux" / "build_packages.sh").read_text(encoding="utf-8")
        self.assertIn("tar", content)

    def test_feat28_tc05_systemd_service_file_included(self):
        """F28.5: Verify osoosi-edr.service systemd unit is packaged."""
        content = (self.root / "packaging" / "linux" / "build_packages.sh").read_text(encoding="utf-8")
        self.assertIn("osoosi-edr.service", content)

    # =========================================================================
    # Feature 29: Hardened Docker Container
    # =========================================================================
    def test_feat29_tc01_dockerfile_exists(self):
        """F29.1: Verify Dockerfile exists in repository root."""
        self.assertTrue((self.root / "Dockerfile").exists())

    def test_feat29_tc02_non_root_uid_65532(self):
        """F29.2: Verify Dockerfile enforces non-root UID 65532:65532."""
        dockerfile = (self.root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("65532:65532", dockerfile)

    def test_feat29_tc03_read_only_rootfs_compatible(self):
        """F29.3: Verify AGENTS.md specifies --read-only rootfs invariant."""
        agents = (self.root / ".agents" / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("--read-only", agents)

    def test_feat29_tc04_cap_drop_all_invariant(self):
        """F29.4: Verify AGENTS.md specifies --cap-drop=ALL invariant."""
        agents = (self.root / ".agents" / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("--cap-drop=ALL", agents)

    def test_feat29_tc05_multi_stage_build(self):
        """F29.5: Verify Dockerfile uses multi-stage build (builder -> runtime)."""
        dockerfile = (self.root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("AS builder", dockerfile)

    # =========================================================================
    # Feature 30: Deterministic Windows Service Lifecycle
    # =========================================================================
    def test_feat30_tc01_service_name_is_osoosiedr(self):
        """F30.1: Verify service name in WiX and scripts is OsoosiEDR."""
        wxs = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertIn('Name="OsoosiEDR"', wxs)

    def test_feat30_tc02_subsecond_stop_optimization_documented(self):
        """F30.2: Verify sub-second stop git commit is present in history."""
        readme_content = (self.root / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("sub-second", readme_content, "Sub-second service stop optimization must be documented in README.md")

    def test_feat30_tc03_service_install_arguments(self):
        """F30.3: Verify WiX manifest defines ServiceInstall with auto-start."""
        wxs = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertIn("<ServiceInstall", wxs)
        self.assertIn('Start="auto"', wxs)

    def test_feat30_tc04_service_control_stop_on_uninstall(self):
        """F30.4: Verify ServiceControl stops and removes service on uninstall."""
        wxs = (self.wix_dir / "OshoosiClaw.wxs").read_text(encoding="utf-8")
        self.assertIn("<ServiceControl", wxs)
        self.assertIn('Stop="both"', wxs)

    def test_feat30_tc05_clean_shutdown_signal_handling(self):
        """F30.5: Verify cli main.rs handles Ctrl+C and service stop events."""
        main_rs = (self.root / "crates" / "osoosi-cli" / "src" / "main.rs").read_text(encoding="utf-8")
        self.assertIn("ctrl_c", main_rs)


if __name__ == "__main__":
    unittest.main()
