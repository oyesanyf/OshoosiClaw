# OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (`OshoosiClaw`) — E2E Testing Infrastructure (`TEST_INFRA.md`)

**Document ID**: `TEST-INFRA-2026-10-20`  
**Version**: `1.2.0`  
**Status**: `ACTIVE`  
**Author**: `teamwork_preview_test_writer`  
**Target Codebase**: `d:\harfile\OshoosiClaw`  

---

## 1. Test Philosophy & Principles

The OpenỌ̀ṣọ́ọ̀sì EDR (`OshoosiClaw`) end-to-end testing infrastructure is designed to provide high-fidelity, reproducible, and adversarial verification of autonomous endpoint detection, prevention, and response capabilities without risking host stability.

### 1.1 Core Principles
1. **Opaque-Box & Requirement-Driven**:
   - Tests are derived strictly from formal user specifications (`ORIGINAL_REQUEST.md`), architecture designs (`PROJECT.md`, `docs/ARCHITECTURE.md`), and public interface contracts.
   - Tests evaluate observable system behavior (process execution control, network isolation state, HTTP/JSON API responses, file system quarantine, and log events) rather than private implementation details.
2. **Absolute Zero-Mock Invariant**:
   - Under no circumstances do test suites execute against synthetic mock stubs, fake signatures, dummy process names, or hardcoded simulated responses.
   - Tests run genuine detection engines, real PE/ELF/WASM structural parsers, Google Magika neural classification, true WinVerifyTrust / Windows Catalog lookups, and live HTTP servers.
3. **Absolute Host OS Immunity Invariant ("Nothing Must Break the OS")**:
   - Invariant: No test, autonomous lockdown, IFEO hook, thread tarpit, Ring-0 driver rule, or firewall rule may terminate, suspend, or block protected OS components:
     - Desktop Shell: `explorer.exe`, `sihost.exe`, `gnome-shell`.
     - Windows Search: `SearchHost.exe`, `SearchIndexer.exe`, `SearchProtocolHost.exe`, `SearchFilterHost.exe`.
     - System Tray: `SecurityHealthSystray.exe`.
     - Core OS Services: `svchost.exe`, `lsass.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `smss.exe`, `systemd`, `dbus-daemon`, `sshd`.
     - Developer Toolchains: `python.exe`, `cargo.exe`, `rustc.exe`, `node.exe`, `git.exe`, `docker.exe`, `code.exe`.
     - Essential Host Networking: Loopback (`127.0.0.1`/`::1`), local management port 3030, DNS (UDP 53), DHCP (UDP 67/68).
4. **Universal Zero-Touch PATH & Environment Protection**:
   - Any installer test, packaging script, or test harness must assert that the system and user `PATH` and environment registry keys are never truncated, overwritten, or mutated.
5. **Tiered Test Pyramid**:
   - **Tier 1 (Feature Coverage)**: Individual feature happy paths with minimal verification dependencies (>=5 test cases per feature for all 30 features = 150 test cases).
   - **Tier 2 (Boundary & Corner Cases)**: Buffer boundaries, extreme limits (0 to 256 MiB), malformed inputs, rapid state cycling, credential brute force, and edge failure recovery.
   - **Tier 3 (Cross-Feature Combinations)**: Pairwise module interactions (Killchain + Tarpit, Quarantine + REA, WebUI + API, Driver + Windows Service).
   - **Tier 4 (Real-World Application Scenarios)**: Realistic end-to-end multi-stage attack and recovery lifecycles (Ransomware, LSASS theft, WebUI SIEM monitoring, service restart under load, and REA quarantine analysis).

---

## 2. Test Architecture & Runner Matrix

The test infrastructure encompasses multi-language harnesses aligned with the project's polyglot architecture:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              E2E TEST RUNNER HARNESSES                                 │
├───────────────────────────┬───────────────────────────────┬────────────────────────────┤
│ Rust Integration Suites   │ Node.js WebUI Test Harness   │ Python & CLI Harnesses     │
│ • cargo test --test ...   │ • node --test dashboard/tests │ • pytest / native python   │
│ • crates/osoosi-core/tests│ • 0-Diff Parity Verifier      │ • tests/comprehensive_...  │
│ • crates/osoosi-types/    │ • View/Button/API Mappings    │ • scripts/test_mesh.ps1    │
└─────────────┬─────────────┴───────────────┬───────────────┴─────────────┬──────────────┘
              │                             │                             │
              ▼                             ▼                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                         E2E UNIFIED ORCHESTRATOR & RUNNER                              │
│                      tests/e2e/e2e_unified_runner.py (or ps1)                          │
│   • Executes Tier 1, Tier 2, Tier 3, and Tier 4 in sequence with structured reporting   │
│   • Generates machine-readable test artifacts and JSON pass/fail metrics               │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Comprehensive Feature Inventory: Tiers 1–4 Mapping

All 30 features from `PROJECT.md` are mapped across Tiers 1 through 4, with at least 5 Tier-1 test cases per feature.

### Feature 1: Hermetic Network Quarantine
- **Description**: Isolates endpoint by blocking non-loopback traffic while strictly allowing `127.0.0.1`/`::1`, WebUI port 3030, DNS (53), and DHCP (67/68).
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat01_loopback_inbound_allowed`: Verifies `127.0.0.1` and `::1` inbound communication is preserved during isolation.
  2. `test_feat01_loopback_outbound_allowed`: Verifies `127.0.0.1` and `::1` outbound communication is preserved during isolation.
  3. `test_feat01_webui_port_3030_preserved`: Verifies TCP port 3030 inbound/outbound is permitted for local and authorized remote operators.
  4. `test_feat01_dns_udp_port_53_allowed`: Verifies UDP 53 outbound queries succeed so threat mesh relays can be resolved.
  5. `test_feat01_dhcp_udp_ports_67_68_allowed`: Verifies DHCP inbound/outbound traffic is allowed to prevent endpoint lease loss.
- **Tier 2 (Boundary & Corner Cases)**: External IPv4 boundary ranges (`0.0.0.0-126.255.255.255` and `128.0.0.0-255.255.255.255`) strictly blocked; IPv6 link-local and multicast handling.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 2 (Process Freeze) and Feature 17 (REST API) during Stage-5 Killchain.
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 1 (Ransomware), Scenario 3 (WebUI SIEM), Scenario 4 (Service Restart).

### Feature 2: Non-Destructive Process Freeze
- **Description**: Suspends untrusted user processes using Win32 `NtSuspendProcess` / Linux `SIGSTOP`, skipping protected OS and developer binaries.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat02_suspend_untrusted_worker_process`: Verifies untrusted child process is suspended without crash.
  2. `test_feat02_system_pid_0_and_4_skipped`: Verifies PID 0 (Idle) and PID 4 (System) are strictly immune from suspension.
  3. `test_feat02_daemon_pid_immune`: Verifies current running EDR process PID is never suspended.
  4. `test_feat02_parent_ancestry_depth_5_immune`: Verifies calling IDE/terminal ancestry up to depth 5 is immune from suspension.
  5. `test_feat02_recorded_in_frozen_pids_state`: Verifies suspended PIDs are safely recorded in `guard.status.frozen_pids`.
- **Tier 2 (Boundary & Corner Cases)**: Non-existent PID suspension handles error cleanly; zero memory leaks during rapid suspension cycles.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 3 (Process Unfreeze) and Feature 4 (Protected Binary Shield).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 1 (Ransomware), Scenario 2 (LSASS Theft).

### Feature 3: Process Unfreeze & Disarm
- **Description**: Resumes previously suspended processes using Win32 `NtResumeProcess` / Linux `SIGCONT`, clearing quarantine rules unconditionally on shutdown.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat03_resume_frozen_processes`: Verifies all PIDs in `frozen_pids` resume normal execution.
  2. `test_feat03_disarm_unauthenticated_exit`: Verifies unconditional disarm executes cleanly on daemon shutdown signal.
  3. `test_feat03_deadmans_watchdog_auto_disarm`: Verifies 1800s (30 min) unattended isolation triggers failsafe recovery.
  4. `test_feat03_firewall_rules_purged_on_disarm`: Verifies all `Osoosi-KillChain-*` firewall rules are removed on disarm.
  5. `test_feat03_ifeo_hooks_purged_on_disarm`: Verifies IFEO debugger registry entries are restored on disarm.
- **Tier 2 (Boundary & Corner Cases)**: Disarm when already disarmed (idempotent no-op); disarm with terminated PIDs.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 1 (Network Quarantine) and Feature 30 (Service Lifecycle).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM Intervention), Scenario 4 (Service Restart).

### Feature 4: Universal Protected Binary Shield
- **Description**: Protects 80+ Windows, Linux, and macOS system, desktop, search, and developer binaries from termination, freeze, or blocking.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat04_windows_search_indexer_protected`: Asserts `SearchHost.exe` and `SearchIndexer.exe` are immune.
  2. `test_feat04_desktop_shell_explorer_protected`: Asserts `explorer.exe` and `sihost.exe` are immune.
  3. `test_feat04_security_health_tray_protected`: Asserts `SecurityHealthSystray.exe` is immune.
  4. `test_feat04_developer_toolchains_protected`: Asserts `python.exe`, `cargo.exe`, `node.exe`, and `git.exe` are immune.
  5. `test_feat04_interpreters_denylist_not_immune`: Asserts LOLBins and interpreters (`powershell.exe`, `cmd.exe`, `mshta.exe`) are NOT shielded as OS shells.
- **Tier 2 (Boundary & Corner Cases)**: Path casing (`SEARCHHOST.EXE` vs `searchhost.exe`), trailing backslashes, mixed slashes, UNC paths.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 2 (Process Freeze), Feature 5 (Ring-0 Driver), and Feature 6 (Linux eBPF).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 1, Scenario 2, Scenario 4.

### Feature 5: Ring-0 Windows Driver Immunity
- **Description**: Windows driver `g_ProtectedImages` table and IOCTL gate reject adding critical OS or developer binaries to kernel blocklist.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat05_driver_rejects_blocking_explorer`: Adding `C:\Windows\explorer.exe` returns `STATUS_ACCESS_DENIED (0xC0000022)`.
  2. `test_feat05_driver_rejects_blocking_searchindexer`: Adding `SearchIndexer.exe` is rejected by `OsoosiIsCriticalSystemImage`.
  3. `test_feat05_driver_rejects_blocking_cargo`: Adding developer tool `cargo.exe` is rejected by kernel driver.
  4. `test_feat05_driver_accepts_blocking_malware`: Adding untrusted payload `C:\Temp\evil.exe` succeeds with `STATUS_SUCCESS`.
  5. `test_feat05_driver_process_creation_interception`: Synchronous `PsSetCreateProcessNotifyRoutineEx` intercepts and blocks untrusted binary.
- **Tier 2 (Boundary & Corner Cases)**: Maximum path length (32,767 chars via `\\?\`), empty path, non-canonical NT device paths (`\Device\HarddiskVolume3\...`).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 4 (Shield) and Feature 30 (Service Lifecycle).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 1 (Ransomware), Scenario 4 (Service Restart).

### Feature 6: Linux eBPF LSM Immunity
- **Description**: Linux eBPF LSM hook `lsm/bprm_check_security` protects `systemd`, `dbus-daemon`, `sshd`, and toolchains; permits loopback/DNS in lockdown.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat06_ebpf_allows_systemd_execution`: Asserts `systemd` bypasses `blocked_paths` BPF map.
  2. `test_feat06_ebpf_allows_sshd_execution`: Asserts `sshd` is preserved to prevent SSH lockout.
  3. `test_feat06_ebpf_blocks_untrusted_elf`: Asserts untrusted binary returns `-EPERM` (`-EACCES`) before execution.
  4. `test_feat06_ebpf_permits_loopback_connect`: Asserts `osoosi_socket_connect` permits `127.0.0.1` and `::1`.
  5. `test_feat06_ebpf_permits_dns_connect`: Asserts UDP port 53 outbound is allowed during lockdown.
- **Tier 2 (Boundary & Corner Cases)**: Symlinks to binaries (`/bin/sh -> /bin/dash`), bind mounts, container PID namespaces.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 4 (Shield) and Feature 28 (Linux Packaging).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 1 (Lockdown), Scenario 4 (Service Recovery).

### Feature 7: Zero-Touch Environment & PATH Protection
- **Description**: Invariant guaranteeing no persistent registry writes to environment hives and no PATH truncation/overwrite.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat07_system_path_not_mutated_by_service`: Verifies system PATH in registry matches pre-test hash.
  2. `test_feat07_user_path_not_mutated_by_service`: Verifies user PATH in registry matches pre-test hash.
  3. `test_feat07_wix_path_is_permanent_and_append`: Verifies WiX manifest defines `Permanent="yes"` and `Part="last"`.
  4. `test_feat07_no_hklm_environment_writes`: Audits daemon execution for 0 writes to `HKLM\...\Environment`.
  5. `test_feat07_no_hkcu_environment_writes`: Audits daemon execution for 0 writes to `HKCU\Environment`.
- **Tier 2 (Boundary & Corner Cases)**: Existing PATH > 2,048 characters; PATH containing quotes, semicolons, and Unicode characters.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 22 (WiX MSI) and Feature 30 (Service Lifecycle).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 4 (Service Restart under Load).

### Feature 8: Tier 1 Outer Envelope Detection (Magika + Magic Bytes)
- **Description**: Uses Google Magika (`magika v1.0.0`) and structural magic bytes to classify outer MIME type and container format.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat08_magika_detects_pe_binary`: Identifies Windows PE executable envelope (`application/x-dosexec`).
  2. `test_feat08_magika_detects_elf_binary`: Identifies Linux ELF binary envelope (`application/x-executable`).
  3. `test_feat08_magika_detects_wasm_binary`: Identifies WebAssembly binary envelope (`application/wasm`).
  4. `test_feat08_magika_detects_sqlite_database`: Identifies SQLite 3 database file (`application/vnd.sqlite3`).
  5. `test_feat08_magika_detects_json_har_archive`: Identifies JSON / HAR network trace archive.
- **Tier 2 (Boundary & Corner Cases)**: Truncated 16-byte headers, all-zero buffers, high-entropy random byte streams, 1-byte file.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 9 (Tier 2 PE CLR Provenance) and Feature 11 (Magika Everywhere).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 5 (Malware Quarantine & REA).

### Feature 9: Tier 2 PE CLR DataDirectory[14] Provenance
- **Description**: Goblin PE Optional Header `DataDirectory[14]` inspection: if zero, binary is unequivocally native; evaluates Rust/Go/native PE without raw BSJB false positives.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat09_native_rust_pe_with_bsjb_string_classified_as_rust`: Verifies `osoosi.exe` with `"BSJB"` literal is classified as `RustBinary`, NOT `.NET`.
  2. `test_feat09_pe_zero_clr_data_directory_never_dotnet`: Verifies PEs with `DataDirectory[14].virtual_address == 0` are never classified as `.NET`.
  3. `test_feat09_genuine_dotnet_pe_classified_as_dotnet`: Verifies genuine C#/.NET PE with non-zero CLR DataDirectory is classified as `DotnetAssembly`.
  4. `test_feat09_go_pe_classified_as_go`: Verifies Go PE containing `\xff Go buildinf:` is classified as `GoBinary`.
  5. `test_feat09_synthetic_buffer_garbage_bsjb_rejected`: Verifies synthetic non-PE buffer with `"BSJB"` followed by non-printable bytes is rejected as `.NET`.
- **Tier 2 (Boundary & Corner Cases)**: PE without Optional Header; PE with DataDirectory size == 0; malformed PE section headers.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 8 (Tier 1 Envelope) and Feature 14 (Multi-Target Decompilation).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 5 (REA Quarantine Analysis).

### Feature 10: REA 256 MiB Read Buffer Cap
- **Description**: Local file inspection buffer cap raised to 256 MiB so binaries like `osoosi.exe` (~85–128 MiB) are analyzed without truncation.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat10_inspect_85mb_rust_binary_without_truncation`: Verifies 85 MiB binary is read completely into memory.
  2. `test_feat10_parse_trailing_sections_of_large_binary`: Verifies section headers at offset > 64 MiB are successfully parsed.
  3. `test_feat10_inspect_128mb_binary_succeeds`: Verifies 128 MiB binary buffer is supported.
  4. `test_feat10_buffer_cap_enforced_at_256mb`: Verifies file reads are safely capped at 256 MiB preventing OOM.
  5. `test_feat10_blake3_hash_computed_over_full_large_file`: Verifies hash covers full file contents up to 256 MiB.
- **Tier 2 (Boundary & Corner Cases)**: Exactly 64 MiB file; exactly 256 MiB file; 256 MiB + 1 byte file (truncated cleanly).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 9 (Provenance) and Feature 15 (YARA Synthesis).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 5 (REA Quarantine Analysis).

### Feature 11: Google Magika Everywhere
- **Description**: Integrates `magika::Session` across REA, file scanners, quarantine inspection, and telemetry reporting.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat11_rea_report_contains_magika_metadata`: Verifies `metadata["magika"]` is populated in REA report.
  2. `test_feat11_magika_evidence_recorded`: Verifies `ReaEvidence` includes Magika label and score.
  3. `test_feat11_quarantine_inspection_invokes_magika`: Verifies quarantined file inspection invokes Magika session.
  4. `test_feat11_telemetry_event_records_magika_label`: Verifies forensic events record Magika content label.
  5. `test_feat11_magika_fallback_on_unrecognized_file`: Verifies safe fallback to structural checks when Magika confidence is low.
- **Tier 2 (Boundary & Corner Cases)**: Empty file (0 bytes); inaccessible file permissions; concurrent Magika session calls.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 8 (Outer Envelope) and Feature 13 (Event-Driven Quarantine).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 5 (REA Analysis).

### Feature 12: Autonomous REA Background Loop
- **Description**: Tokio background task executes periodic reverse-engineering sweeps across binaries, databases, and quarantine artifacts.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat12_autonomous_loop_starts_at_boot`: Verifies `start_autonomous_loop(60)` task is active at daemon boot.
  2. `test_feat12_periodic_sweep_generates_reports`: Verifies sweep generates `ReaInvestigationReport` records.
  3. `test_feat12_sweep_persists_reports_to_sqlite`: Verifies reports are saved to `database/osoosi.db`.
  4. `test_feat12_sweep_tolerates_corrupt_artifact`: Verifies corrupt sample in sweep directory does not crash the loop.
  5. `test_feat12_rest_api_reports_autonomous_status`: Verifies `GET /api/rea/v1/status` reports loop health.
- **Tier 2 (Boundary & Corner Cases)**: Sweep directory empty; sweep directory with 1,000 files; rapid cancellation of background task.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 13 (Quarantine REA) and Feature 17 (REST API).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM Monitoring), Scenario 5 (REA Analysis).

### Feature 13: Event-Driven Quarantine REA & YARA
- **Description**: Automatically triggers deep REA reverse-engineering and YARA hot-synthesis when an artifact is quarantined.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat13_quarantine_event_triggers_rea`: Quarantining a test binary schedules REA decompilation.
  2. `test_feat13_yara_rule_synthesized_for_quarantined_file`: Verifies multi-token YARA rule is generated.
  3. `test_feat13_synthesized_yara_rule_compiles`: Verifies generated YARA rule compiles with `yara-x`.
  4. `test_feat13_quarantine_metadata_records_analysis_id`: Verifies quarantine table stores link to REA investigation ID.
  5. `test_feat13_non_blocking_async_execution`: Verifies quarantine operation completes immediately without waiting for REA.
- **Tier 2 (Boundary & Corner Cases)**: Zero-byte quarantined file; read-only quarantine folder; duplicate quarantine events.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 10 (256 MiB Read Buffer) and Feature 15 (YARA Synthesis).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 1 (Ransomware), Scenario 5 (REA Analysis).

### Feature 14: WebUI 19 Views & 5 Modals Wiring
- **Description**: All 19 navigation views, sub-tabs, and 5 operational modals in `dashboard/src/` and `dist/` active with zero dead clicks.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat14_overview_view_active`: Verifies Overview view renders with telemetry statistics.
  2. `test_feat14_killchain_view_active`: Verifies Killchain stage escalation and controls view renders.
  3. `test_feat14_rea_view_active`: Verifies Autonomous REA console renders with report feed.
  4. `test_feat14_forensics_view_active`: Verifies Forensic storytelling and timeline views render.
  5. `test_feat14_operational_modals_render`: Verifies Disarm Modal, Quarantine Modal, and Rule Modal render.
- **Tier 2 (Boundary & Corner Cases)**: Rapid tab switching; hash route manipulation; viewport resizing (responsive layout).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 15 (128 Buttons) and Feature 16 (0-Diff Parity).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM WebUI Monitoring).

### Feature 15: WebUI 128 Buttons Event Handlers
- **Description**: All 128 buttons in WebUI wired to live frontend event handlers or inline onclicks with zero dead clicks.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat15_killchain_isolate_button_wired`: Verifies Isolate button dispatches POST to `/api/killchain/isolate`.
  2. `test_feat15_killchain_disarm_button_wired`: Verifies Disarm button dispatches POST to `/api/killchain/disarm`.
  3. `test_feat15_rea_analyze_button_wired`: Verifies Analyze button dispatches POST to `/api/rea/v1/analyze`.
  4. `test_feat15_siquery_execute_button_wired`: Verifies Execute button dispatches POST to `/api/siquery/query`.
  5. `test_feat15_all_128_buttons_have_listeners`: Audits DOM elements for click handler registration.
- **Tier 2 (Boundary & Corner Cases)**: Double-clicking action buttons; clicking during network latency; disabled state styling.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 17 (REST API Routes) and Feature 19 (Node.js Test Suite).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM Monitoring).

### Feature 16: WebUI 0-Diff Parity Invariant
- **Description**: Exact byte-for-byte SHA-256 match between `dashboard/src/` and `dashboard/dist/`.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat16_index_html_identical`: Verifies SHA-256 of `src/index.html` equals `dist/index.html`.
  2. `test_feat16_app_js_identical`: Verifies SHA-256 of `src/app.js` equals `dist/app.js`.
  3. `test_feat16_styles_css_identical`: Verifies SHA-256 of `src/styles.css` equals `dist/styles.css`.
  4. `test_feat16_assets_directory_identical`: Verifies all icons and assets match between src and dist.
  5. `test_feat16_git_diff_no_index_zero_exit`: Verifies `git diff --no-index dashboard/src dashboard/dist` returns 0.
- **Tier 2 (Boundary & Corner Cases)**: CRLF vs LF line endings normalized; whitespace diffs detected; extra untracked files in dist.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 14 (Views/Modals) and Feature 18 (WiX Packaging).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM Monitoring).

### Feature 17: Backend REST API Route Coverage
- **Description**: 158 Axum REST API routes covering 100% of frontend endpoints on port 3030 with zero mocks.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat17_get_api_status`: `GET /api/status` returns daemon health JSON.
  2. `test_feat17_get_api_threats`: `GET /api/threats` returns list of active threats.
  3. `test_feat17_get_api_killchain_status`: `GET /api/killchain/status` returns current stage and isolation status.
  4. `test_feat17_post_api_rea_analyze`: `POST /api/rea/v1/analyze` triggers target analysis.
  5. `test_feat17_post_api_siquery`: `POST /api/siquery/query` executes SQL query against virtual schema.
- **Tier 2 (Boundary & Corner Cases)**: Missing auth token (returns 401); malformed JSON body (returns 400); invalid HTTP methods (returns 405).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 1 (Network Quarantine) and Feature 15 (WebUI Buttons).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM Monitoring).

### Feature 18: WiX Offline Dashboard Packaging
- **Description**: WiX manifest packages `chart.min.js`, `lucide.min.js`, and static assets for completely air-gapped SIEM operation.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat18_chartjs_included_in_wxs`: Verifies `chart.min.js` component exists in `wix/OshoosiClaw.wxs`.
  2. `test_feat18_lucide_included_in_wxs`: Verifies `lucide.min.js` component exists in `wix/OshoosiClaw.wxs`.
  3. `test_feat18_offline_dashboard_loads_without_cdn`: Verifies WebUI loads cleanly with 0 external network requests.
  4. `test_feat18_all_dashboard_assets_packaged`: Verifies all HTML, JS, CSS, and SVG files mapped to INSTALLFOLDER.
  5. `test_feat18_wix_build_validates_component_guids`: Verifies WiX manifest compiles with valid component GUIDs.
- **Tier 2 (Boundary & Corner Cases)**: Air-gapped network environment (DNS resolution fails, UI must render fully).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 16 (0-Diff Parity) and Feature 22 (MSI Build).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM Monitoring).

### Feature 19: Node.js WebUI Test Suite
- **Description**: Native Node.js test suite (`node --test dashboard/tests/*.test.mjs`) verifying views, buttons, API bindings, and parity.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat19_node_test_runner_executes`: Runs `node --test dashboard/tests/*.test.mjs` with 100% pass.
  2. `test_feat19_tests_verify_all_views`: Verifies 19 views exist in DOM.
  3. `test_feat19_tests_verify_all_modals`: Verifies 5 operational modals exist in DOM.
  4. `test_feat19_tests_verify_all_buttons`: Verifies 128 buttons have active event bindings.
  5. `test_feat19_tests_verify_0_diff_parity`: Verifies src vs dist parity in Node.js test environment.
- **Tier 2 (Boundary & Corner Cases)**: Node.js version compatibility (Node 18, 20, 22); zero external npm dependencies required.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 14, 15, 16.
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 3 (SIEM Monitoring).

### Feature 20: Comprehensive Security Audit
- **Description**: Security audit across all crates, drivers, and scripts for memory safety, lock poisoning, async deadlocks, and auth/CSRF/XSS.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat20_auth_tokens_use_constant_time_eq`: Verifies `subtle::ConstantTimeEq` on all token verifications.
  2. `test_feat20_no_blocking_read_in_async_tokio`: Verifies 0 calls to `blocking_read`/`blocking_write` in async tasks.
  3. `test_feat20_dashmap_lock_hygiene`: Verifies no `.iter()` called while holding mutable `.entry()` on same DashMap.
  4. `test_feat20_cookies_httponly_samesite_strict`: Verifies session cookies enforce HttpOnly and SameSite=Strict.
  5. `test_feat20_path_traversal_prevention`: Verifies `Path::join` rejects `..`, `%2e%2e`, UNC, and drive letters.
- **Tier 2 (Boundary & Corner Cases)**: Multi-threaded race conditions; malicious URL encoding; deeply nested directory traversal.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 17 (REST API) and Feature 24 (Adversarial Hardening).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 2 (LSASS Access), Scenario 3 (SIEM Monitoring).

### Feature 21: Full Workspace Test Suite Pass
- **Description**: `cargo test --workspace` passes 100% of unit and integration tests with 0 failures across all 36 workspace crates.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat21_osoosi_types_passes`: All unit tests in `osoosi-types` pass.
  2. `test_feat21_osoosi_core_passes`: All unit and integration tests in `osoosi-core` pass.
  3. `test_feat21_osoosi_runtime_passes`: All tests in `osoosi-runtime` pass.
  4. `test_feat21_osoosi_model_passes`: All ML threat model and classification tests pass.
  5. `test_feat21_osoosi_dashboard_passes`: All Axum route tests in `osoosi-dashboard` pass.
- **Tier 2 (Boundary & Corner Cases)**: Single-threaded vs multi-threaded test execution (`--test-threads=1`).
- **Tier 3 (Cross-Feature Combinations)**: All crates.
- **Tier 4 (Real-World Scenarios)**: All scenarios.

### Feature 22: RAPTOR Security Scan Verification
- **Description**: Full-suite RAPTOR security scan (`Invoke-RaptorScan.ps1 -Mode all`) completes with 0 verified or exploitable findings.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat22_raptor_semgrep_clean`: Static analysis passes with 0 exploitable findings.
  2. `test_feat22_raptor_pqc_readiness`: Verifies post-quantum crypto algorithms (ML-KEM / Ed25519) conform.
  3. `test_feat22_raptor_secret_scan_clean`: Verifies no hardcoded secrets or API tokens exist in source.
  4. `test_feat22_raptor_memory_safety_clean`: Verifies unsafe Rust blocks are documented and audited.
  5. `test_feat22_raptor_supply_chain_clean`: Verifies all dependencies in Cargo.lock match security advisories.
- **Tier 2 (Boundary & Corner Cases)**: Scan in offline mode; scan on modified unstaged tree.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 20 (Security Audit).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 2.

### Feature 23: E2E Requirement-Driven Test Suite
- **Description**: Opaque-box test suite covering Tiers 1-4 derived from specifications, publishing `TEST_READY.md`.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat23_test_infra_document_complete`: Verifies `TEST_INFRA.md` exists and defines all 30 features.
  2. `test_feat23_test_ready_document_complete`: Verifies `TEST_READY.md` exists with test runner commands.
  3. `test_feat23_e2e_suite_executes_all_tiers`: Verifies runner executes Tiers 1-4 sequentially.
  4. `test_feat23_structured_test_results_emitted`: Verifies JSON report is generated with pass/fail counts.
  5. `test_feat23_zero_facade_tests_asserted`: Verifies every test asserts against genuine system invariants.
- **Tier 2 (Boundary & Corner Cases)**: Test suite execution under simulated host load; test execution with degraded privileges.
- **Tier 3 (Cross-Feature Combinations)**: All features.
- **Tier 4 (Real-World Scenarios)**: All scenarios.

### Feature 24: Adversarial Coverage Hardening
- **Description**: White-box Challenger analysis and Tier 5 adversarial test suite hardening against evasion techniques.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat24_process_hollowing_detected`: Detects unmapped executable memory in benign parent.
  2. `test_feat24_amsi_bypass_patching_detected`: Detects memory patching of `AmsiScanBuffer`.
  3. `test_feat24_etw_ti_tamper_detected`: Detects tampering with kernel ETW threat intelligence provider.
  4. `test_feat24_direct_syscall_evasion_detected`: Detects unhooked direct system calls from untrusted memory.
  5. `test_feat24_ntfs_ads_execution_blocked`: Detects execution attempt from Alternate Data Stream (`file.txt:evil.exe`).
- **Tier 2 (Boundary & Corner Cases)**: Byte-level polymorphic variations; shellcode encodings (XOR, RC4, S-Box).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 4 (Shield) and Feature 5 (Ring-0 Driver).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 1 (Ransomware), Scenario 2 (LSASS).

### Feature 25: Windows WiX MSI Build & Authenticode
- **Description**: Compiles `OshoosiClaw.msi` installer; signs all `.exe`, `.dll`, `.sys`, and `.msi` artifacts with native Windows 10 SDK `signtool.exe` (SHA-256 + DigiCert RFC 3161 timestamp).
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat25_wix_msi_compiles_cleanly`: Verifies WiX v5 compiles `OshoosiClaw.msi` without error.
  2. `test_feat25_authenticode_signature_valid`: Verifies `Get-AuthenticodeSignature` on `osoosi.exe` is valid.
  3. `test_feat25_companion_binaries_signed`: Verifies `osoosi_inject.dll`, `osoosi-auditor.exe` are signed.
  4. `test_feat25_rfc_3161_timestamp_present`: Verifies signature contains RFC 3161 counter-signature timestamp.
  5. `test_feat25_wdac_device_guard_compliant`: Verifies signature structure is compliant with Windows Device Guard.
- **Tier 2 (Boundary & Corner Cases)**: Missing timestamp server (fallback retry); locked binary during signing (hardlink break).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 7 (PATH Protection) and Feature 26 (WDSI).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 4 (Service Lifecycle).

### Feature 26: Microsoft WDSI Automated Submission
- **Description**: Submits signed release binaries and MSI to Microsoft Security Intelligence via `python scripts/submit_to_wdsi.py --all --no-launch`.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat26_wdsi_script_validates_binaries`: Verifies script discovers and verifies all target binaries.
  2. `test_feat26_wdsi_sha256_hashes_computed`: Verifies SHA-256 digests match file contents.
  3. `test_feat26_wdsi_metadata_payload_structured`: Verifies JSON submission report conforms to schema.
  4. `test_feat26_wdsi_multi_tier_fallback`: Verifies graceful fallback across OAuth, Web, and Offline report tiers.
  5. `test_feat26_wdsi_audit_log_written`: Verifies submission history is written to local audit log.
- **Tier 2 (Boundary & Corner Cases)**: Offline / disconnected network during submission; file size > 500 MB.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 25 (Signing) and Feature 27 (GitHub Release).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 4 (Packaging).

### Feature 27: GitHub Release & SLSA Attestation Sync
- **Description**: Packages in-toto SLSA DSSE provenance and detached GPG signatures, uploading release assets to GitHub Releases via `python scripts/update_github_release_msi.py`.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat27_intoto_dsse_provenance_generated`: Verifies `.intoto.jsonl` contains SLSA v1.0 predicate.
  2. `test_feat27_sha256_checksums_file_generated`: Verifies `SHA256SUMS` covers all release assets.
  3. `test_feat27_gpg_detached_signatures_generated`: Verifies `.sig` and `.asc` files are produced.
  4. `test_feat27_github_release_target_resolved`: Verifies script resolves latest release tag on GitHub repo.
  5. `test_feat27_idempotent_asset_upload`: Verifies uploading existing asset replaces or validates without crashing.
- **Tier 2 (Boundary & Corner Cases)**: GitHub API rate limiting; missing GPG key (clear error message).
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 25 (MSI) and Feature 26 (WDSI).
- **Tier 4 (Real-World Scenarios)**: Packaging pipeline.

### Feature 28: Multi-Distro Linux Packaging
- **Description**: Packages `.deb`, `.rpm`, and `.tar.gz` for Debian, Ubuntu, RHEL, and Fedora with systemd unit files via `packaging/linux/build_packages.sh`.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat28_deb_package_structure_valid`: Verifies `control`, `postinst`, and systemd service in `.deb`.
  2. `test_feat28_rpm_spec_syntax_valid`: Verifies RPM spec file defines correct dependencies and scripts.
  3. `test_feat28_tarball_contains_binaries_and_service`: Verifies `.tar.gz` includes `osoosi` and `osoosi.service`.
  4. `test_feat28_systemd_unit_file_hardened`: Verifies `ProtectSystem=strict` and `CapabilityBoundingSet` in unit file.
  5. `test_feat28_packages_copied_to_deploy_dir`: Verifies artifacts sync to `deploy/linux/`.
- **Tier 2 (Boundary & Corner Cases)**: Target directory permissions; missing `rpmbuild` or `dpkg-deb` on non-Linux host.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 6 (Linux eBPF) and Feature 29 (Docker).
- **Tier 4 (Real-World Scenarios)**: Linux deployment.

### Feature 29: Hardened Docker Container
- **Description**: Multi-stage Docker build producing unprivileged container (`UID 65532:65532`), `0` SUID/SGID bits, ready for read-only rootfs (`ghcr.io/oyesanyf/oshoosiclaw:1.2.0`).
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat29_dockerfile_uses_digest_pinned_base`: Verifies base image uses SHA-256 digest pin.
  2. `test_feat29_container_runs_as_non_root_uid`: Verifies `USER 65532:65532` in Dockerfile.
  3. `test_feat29_zero_suid_sgid_files_in_image`: Verifies no binaries have SUID/SGID bits set.
  4. `test_feat29_read_only_rootfs_compatible`: Verifies container runs with `--read-only` flag.
  5. `test_feat29_cap_drop_all_compatible`: Verifies container operates cleanly under `--cap-drop=ALL`.
- **Tier 2 (Boundary & Corner Cases)**: Ephemeral storage write attempts; seccomp profile violations.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 20 (Security Audit) and Feature 28 (Linux Packaging).
- **Tier 4 (Real-World Scenarios)**: Containerized SIEM / sensor deployment.

### Feature 30: Deterministic Windows Service Lifecycle
- **Description**: `OsoosiEDR` Windows service starts, runs, and stops deterministically in `< 1.5s` without disrupting OS components.
- **Tier 1 (Feature Coverage Happy Paths)**:
  1. `test_feat30_service_starts_in_under_1500ms`: Measures startup latency < 1,500 ms.
  2. `test_feat30_service_stops_in_under_1500ms`: Measures shutdown latency < 1,500 ms.
  3. `test_feat30_service_status_query_running`: Verifies `Get-Service OsoosiEDR` reports `Status = Running`.
  4. `test_feat30_desktop_shell_unaffected_during_restart`: Verifies `explorer.exe` CPU/memory stable during service restart.
  5. `test_feat30_windows_search_unaffected_during_restart`: Verifies `SearchHost.exe` remains responsive during service restart.
- **Tier 2 (Boundary & Corner Cases)**: Service stop during active threat correlation; service restart under 100% CPU stress.
- **Tier 3 (Cross-Feature Combinations)**: Paired with Feature 3 (Unfreeze & Disarm), Feature 5 (Driver), and Feature 7 (PATH).
- **Tier 4 (Real-World Scenarios)**: Participates in Scenario 4 (Service Restart under Load).

---

## 4. Real-World Application Scenarios (Tier 4)

The test infrastructure defines 5 comprehensive, realistic end-to-end operational scenarios:

### Scenario 1: Multi-Stage Ransomware Attack Simulation & Autonomous Hermetic Lockdown
- **Objective**: Verify that simulated ransomware rapid file modification triggers killchain stage escalation, hermetic network isolation, and process suspension, while strictly preserving protected host processes and loopback network communication.
- **Attack Flow**:
  1. Attacker drops synthetic high-speed encryption worker in user directory (`C:\Users\Public\ransom_sim.exe`).
  2. Worker rapidly touches and modifies 50 honeypot files in monitored folder.
  3. Behavioral anomaly voter and heuristic ML engine detect anomalous entropy increase (> 7.5) and mass rename events.
  4. Core Orchestrator escalates Killchain:
     - Stage 1: Initial Reconnaissance -> Stage 2: Foothold -> Stage 3: Privilege Escalation -> Stage 4: Lateral Prep -> Stage 5: Active Impact / Ransomware.
  5. Autonomous Response triggers:
     - Hermetic Network Quarantine: blocks non-loopback traffic; loopback `127.0.0.1:3030`, DNS (53), DHCP (67/68) preserved.
     - Process Freeze: Win32 `NtSuspendProcess` halts `ransom_sim.exe`.
  6. OS Immunity Verification:
     - Asserts `explorer.exe`, `SearchHost.exe`, `SecurityHealthSystray.exe`, and developer tools (`python.exe`, `cargo.exe`) remain completely unaffected and responsive.
     - Asserts `127.0.0.1:3030` WebUI remains accessible.
  7. Operator Disarm:
     - Authenticates via master token, releases isolation, resumes processes, and purges firewall rules.

### Scenario 2: LSASS Credential Access Simulation & Thread Tarpit Suspension
- **Objective**: Verify that unauthorized attempts to access `lsass.exe` memory handles trigger immediate thread-level tarpitting and process shielding without disrupting system authentication.
- **Attack Flow**:
  1. Untrusted test process attempts `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsass_pid)`.
  2. Runtime Tarpit (`crates/osoosi-runtime/src/tarpit.rs`) intercepts the suspicious handle acquisition.
  3. Target untrusted thread is immediately placed in an active tarpit state (sleep loop / suspended thread).
  4. System LSASS process and `winlogon.exe` remain 100% operational.
  5. Security event is logged to SQLite `threats` table and SIEM telemetry stream.
  6. Operator inspects incident details via `/api/threats` and approves permanent termination of the adversary process.

### Scenario 3: Real-Time SIEM WebUI Monitoring, Multi-Tab Investigation & Operator Intervention
- **Objective**: Verify that operator can navigate all 19 views and 5 modals in the Axum WebUI, monitor live telemetry streams, trigger an REA sweep, and execute an isolated disarm with zero console errors and zero dead clicks.
- **Operational Flow**:
  1. Automated headless browser / Node.js harness opens `http://127.0.0.1:3030`.
  2. Harness authenticates via session token.
  3. Navigates sequentially across all 19 views: Overview, Threat Map, Kill Chain, Forensics, Autonomous REA, Policy, Siquery, Audit, Settings, etc.
  4. Clicks 10 key operational buttons:
     - Trigger Autonomous REA Sweep (`POST /api/rea/v1/autonomous-sweep`).
     - Query Siquery SQLite virtual table (`POST /api/siquery/query`).
     - View Threat Details modal.
     - Test Isolate Host button -> Disarm Host button.
  5. Asserts every REST call returns `{ "success": true, ... }` with valid JSON payload.
  6. Asserts 0 console errors and 0 unhandled promise rejections.

### Scenario 4: High-Stress Windows Service Recovery & Disarm Watchdog Fail-Safe
- **Objective**: Verify deterministic start, run, and stop of `OsoosiEDR` Windows service under simulated system load, proving that dead-man's watchdog auto-restores host connectivity if operator disconnects.
- **Operational Flow**:
  1. System load simulator generates 50 concurrent worker threads consuming 80% CPU.
  2. Service supervisor initiates `OsoosiEDR` startup; measures time to running state (< 1,500 ms).
  3. Service engages emergency network quarantine.
  4. Supervisor simulates operator network severance (dead-man condition).
  5. Watchdog timer triggers failsafe auto-disarm (`execute_host_disarm_unauthenticated`).
  6. Service stop command is issued; measures shutdown latency (< 1,500 ms).
  7. Verification:
     - All firewall rules cleanly removed.
     - System `PATH` and registry environment variables remain 100% unmodified.
     - Developer tools (`python`, `cargo`) continue executing without interruption.

### Scenario 5: Dropped Multi-Format Malware Quarantine, Tiered REA Reverse-Engineering & YARA Synthesis
- **Objective**: Verify the complete dropped artifact lifecycle: ingestion of mixed binary formats, Tier 1 Google Magika MIME classification, Tier 2 PE CLR DataDirectory[14] structural provenance (isolating native Rust `osoosi.exe` from .NET assemblies), quarantine isolation, deep decompilation, and automated YARA synthesis.
- **Operational Flow**:
  1. Ingestion: Drops 3 test artifacts in monitored incoming folder:
     - Artifact A: Release `osoosi.exe` native Rust PE binary (~82 MiB) containing literal `"BSJB"` in code.
     - Artifact B: Genuine .NET CIL assembly executable.
     - Artifact C: ELF Linux executable.
  2. Quarantine: Core Orchestrator quarantines Artifact B and A.
  3. Event-Driven REA Trigger:
     - Quarantine subsystem invokes `AutonomousReaEngine` in background.
  4. 2-Tier Classification Pipeline:
     - Tier 1: Google Magika detects `application/x-dosexec` for A & B, `application/x-executable` for C.
     - Tier 2: Goblin parses PE Optional Header `DataDirectory[14]`.
       - For Artifact A: `virtual_address == 0`. Binary is classified as `RustBinary`. Raw `"BSJB"` byte match is completely bypassed.
       - For Artifact B: `virtual_address > 0`. CLR parser engages, validates `"BSJB"`, ASCII `"v..."` CLR version, and stream headers. Classified as `DotnetAssembly`.
  5. 256 MiB Buffer: Artifact A (82 MiB) is read in full without 64 MiB truncation; all trailing sections parsed.
  6. YARA Synthesis: REA engine synthesizes high-entropy, multi-token YARA-X rules for quarantined artifacts.
  7. Verification: Hot-loaded YARA rule compiles and detects Artifact B.

---

## 5. Directory Layout & Artifact Locations

```
d:\harfile\OshoosiClaw\
├── TEST_INFRA.md                   # This document: Comprehensive Test Architecture & Feature Matrix
├── TEST_READY.md                   # Generated test runner commands and verification summary
├── dashboard/
│   └── tests/
│       ├── webui_views.test.mjs    # Node.js test suite: 19 Views & 5 Modals
│       ├── webui_buttons.test.mjs  # Node.js test suite: 128 Buttons & Event Handlers
│       └── webui_parity.test.mjs   # Node.js test suite: 0-Diff Parity Verifier
├── tests/
│   ├── e2e/
│   │   ├── tier1_features_test.py  # Tier 1: 150 feature happy path tests
│   │   ├── tier2_boundary_test.py  # Tier 2: Limits, boundaries, empty buffers, rapid cycling
│   │   ├── tier3_pairwise_test.py  # Tier 3: Cross-feature pairwise interactions
│   │   ├── tier4_scenarios_test.py # Tier 4: 5 Real-world operational scenarios
│   │   └── run_e2e_suite.py        # Unified Python E2E runner (JSON/console reporting)
│   └── run_e2e.ps1                 # Canonical PowerShell test execution wrapper
└── crates/
    └── osoosi-core/
        └── tests/
            ├── host_adversarial_tests.rs           # Core host adversarial tests
            └── e2e_tiered_classification_tests.rs # Rust integration tests for 2-Tier REA & Immunity
```

---

## 6. Execution Command Summary

To execute the test suites across all tiers:

```powershell
# 1. Execute Unified E2E Test Suite (Tiers 1 - 4)
python tests/e2e/run_e2e_suite.py --all

# 2. Execute Node.js WebUI Test Suite (Feature 14-16, 19)
node --test dashboard/tests/*.test.mjs

# 3. Execute Rust Core Host Immunity & Classification Integration Tests
$env:CARGO_REGISTRIES_CRATES_IO_PROTOCOL = "git"
cargo test -p osoosi-core --test host_adversarial_tests
```
