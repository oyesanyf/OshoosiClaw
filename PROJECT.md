# Project: OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (`OshoosiClaw`)

## Architecture
- **Core Orchestrator**: `crates/osoosi-core` coordinates killchain state, autonomous lockdowns, tarpit isolation, quarantine, and telemetry.
- **Autonomous REA Engine**: `crates/osoosi-core/src/rea.rs` provides 2-tier binary classification (Tier 1 Magika MIME + Tier 2 Structural PE/CLR DataDirectory[14] Provenance), multi-format bytecode decompilation, autonomous background sweep, and automated YARA synthesis.
- **WebUI & API Console**: `crates/osoosi-dashboard` provides 158 Axum REST routes on port 3030 connecting 100% of frontend calls to genuine EDR engines (zero mocks); `dashboard/src/` and `dashboard/dist/` maintain strict 0-diff parity across 19 views, 5 operational modals, and 128 buttons.
- **Enforcement Layers**:
  - User-space: `crates/osoosi-runtime/src/tarpit.rs` (thread freeze), `crates/osoosi-core/src/blocking_manager.rs`, `firewall.rs` (WFP/netsh & iptables).
  - Ring-0 Windows Driver: `driver/windows/src/osoosi_driver.c` intercepts process creation with `STATUS_ACCESS_DENIED` (`0xC0000022`) while whitelisting `g_ProtectedImages`.
  - Linux eBPF LSM Probe: `ebpf/src/osoosi_probe.bpf.c` hooks `lsm/bprm_check_security` returning `-EPERM` while whitelisting `is_critical_linux_binary` and permitting loopback/DNS/DHCP during lockdown.
- **Packaging & Supply Chain**:
  - WiX v5 MSI: `wix/OshoosiClaw.wxs` packages service, driver, CLI, dashboard, and offline scripts with PATH immutability (`Permanent="yes"`, `Part="last"`).
  - Authenticode: Native Windows 10 SDK `signtool.exe` (SHA-256 + DigiCert RFC 3161 timestamp).
  - WDSI: Automated submission via `scripts/submit_to_wdsi.py --all --no-launch`.
  - Release Sync: GitHub Release and SLSA in-toto DSSE provenance sync via `scripts/update_github_release_msi.py`.
  - Multi-Distro Linux: `packaging/linux/build_packages.sh` (.deb, .rpm, .tar.gz).
  - Hardened Docker: `Dockerfile` targeting `ghcr.io/oyesanyf/oshoosiclaw:1.2.0` (UID 65532:65532, read-only rootfs).

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---|---|---|---|
| 1 | Hermetic Network Quarantine | Blocks external traffic; strictly allows loopback (`127.0.0.1`/`::1`), WebUI port 3030, DNS (53), and DHCP (67/68) | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Non-Destructive Process Freeze | Win32 `NtSuspendProcess` / Linux `SIGSTOP` preserving daemon, parent lineage, desktop shell, search, and developer tools | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Process Unfreeze & Disarm | Win32 `NtResumeProcess` / Linux `SIGCONT` and unconditional cleanup on daemon exit | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Universal Protected Binary Shield | Protects 80+ Windows/Linux/macOS desktop, search, tray, core services, and developer toolchains (`python`, `cargo`, `node`, `git`) | M1 | ORIGINAL_REQUEST §R1 |
| 5 | Ring-0 Windows Driver Immunity | Driver `g_ProtectedImages` protects core OS, search, tray, and developer binaries from kernel blocks | M1 | ORIGINAL_REQUEST §R1 |
| 6 | Linux eBPF LSM Immunity | eBPF probe protects systemd, dbus, sshd, and developer toolchains; permits DNS/DHCP in lockdown | M1 | ORIGINAL_REQUEST §R1 |
| 7 | Zero-Touch Environment & PATH Protection | Invariant guaranteeing no registry writes to environment hives and no PATH truncation/overwrite | M1 | ORIGINAL_REQUEST §R1 |
| 8 | Tier 1 Outer Envelope Detection | Google Magika (`magika v1.0.0`) + magic bytes to classify outer MIME/container format | M2 | Follow-up 2 & 3 |
| 9 | Tier 2 PE CLR DataDirectory[14] Provenance | Goblin PE Optional Header DataDirectory[14] check; if zero, unequivocally native (raw BSJB scan bypassed); evaluates Rust/Go/PE | M2 | Follow-up 1 & 3 |
| 10 | REA 256 MiB Read Buffer Cap | Local file inspection buffer raised to 256 MiB so binaries like `osoosi.exe` (~75.7–128 MiB) are inspected completely | M2 | Follow-up 1 |
| 11 | Google Magika Everywhere | Integrates `magika::Session` across REA, file scanners, quarantine inspection, and telemetry reporting | M2 | Follow-up 2 |
| 12 | Autonomous REA Background Loop | Wire `AutonomousReaEngine::start_autonomous_loop(60)` at daemon startup | M2 | ORIGINAL_REQUEST §R2 |
| 13 | Event-Driven Quarantine REA & YARA | Triggers deep REA decompilation and automated YARA synthesis when suspicious artifact is quarantined | M2 | ORIGINAL_REQUEST §R2 |
| 14 | WebUI 19 Views & 5 Modals Wiring | All navigation tabs, sub-tabs, and modals in `dashboard/src/` and `dist/` active with zero dead clicks | M3 | ORIGINAL_REQUEST §R3 |
| 15 | WebUI 128 Buttons Event Handlers | All 128 buttons wired to live frontend event handlers or inline onclicks | M3 | ORIGINAL_REQUEST §R3 |
| 16 | WebUI 0-Diff Parity Invariant | Exact byte-for-byte SHA-256 match between `dashboard/src/` and `dashboard/dist/` | M3 | ORIGINAL_REQUEST §R3 |
| 17 | Backend REST API Route Coverage | 158 Axum routes covering 100% of 98 frontend endpoints with zero mocks | M3 | ORIGINAL_REQUEST §R3 |
| 18 | WiX Offline Dashboard Packaging | Add `chart.min.js` and `lucide.min.js` to `DashboardAssets` in `wix/OshoosiClaw.wxs` | M3 | Explorer Survey |
| 19 | Node.js WebUI Test Suite | `node --test dashboard/tests/*.test.mjs` verifying views, buttons, API bindings, and parity | M3 | ORIGINAL_REQUEST §R3 |
| 20 | Comprehensive Security Audit | Audit all crates, drivers, eBPF, and scripts for memory safety, lock poisoning, async deadlocks, auth/CSRF/XSS | M4 | ORIGINAL_REQUEST §R2 |
| 21 | Full Workspace Test Suite Pass | `cargo test --workspace` passes 100% with 0 failures across all 36 crates | M4 | ORIGINAL_REQUEST Acceptance |
| 22 | RAPTOR Security Scan Verification | Full-suite RAPTOR scan completes with 0 verified or exploitable findings | M4 | ORIGINAL_REQUEST Acceptance |
| 23 | E2E Requirement-Driven Test Suite | Opaque-box test suite covering Tiers 1-4 derived from specifications | M5 | Project Dual Track |
| 24 | Adversarial Coverage Hardening | White-box Challenger analysis and Tier 5 adversarial test suite hardening | M5 | Project Dual Track |
| 25 | Windows WiX MSI Build & Authenticode | `OshoosiClaw.msi` compiled and Authenticode signed with SHA-256 + DigiCert RFC 3161 timestamp | M6 | ORIGINAL_REQUEST Acceptance |
| 26 | Microsoft WDSI Automated Submission | Automated submission of release binaries to Microsoft Security Intelligence | M6 | ORIGINAL_REQUEST Acceptance |
| 27 | GitHub Release & SLSA Attestation Sync | Sync MSI, in-toto DSSE provenance, and detached GPG signatures to GitHub Releases | M6 | ORIGINAL_REQUEST Acceptance |
| 28 | Multi-Distro Linux Packaging | `.deb`, `.rpm`, `.tar.gz` built with systemd service via `packaging/linux/build_packages.sh` | M6 | ORIGINAL_REQUEST Acceptance |
| 29 | Hardened Docker Container | `ghcr.io/oyesanyf/oshoosiclaw:1.2.0` (UID 65532:65532, read-only rootfs, 0 SUID/SGID) | M6 | ORIGINAL_REQUEST Acceptance |
| 30 | Deterministic Windows Service Lifecycle | `OsoosiEDR` Windows service starts, runs, and stops in < 1.5s without disrupting OS components | M6 | ORIGINAL_REQUEST Acceptance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| M1 | Host OS & Developer Immunity Enforcement | Core, runtime tarpit, remediation, Windows driver `g_ProtectedImages`, and eBPF LSM binary/network filters; unit tests in `crates/osoosi-core` | none | IN_PROGRESS |
| M2 | Tiered REA Pipeline, Engine Wiring & Magika | 2-Tier classification in `rea.rs`, 256 MiB buffer, Magika integration, daemon boot loop, event-driven quarantine trigger; unit tests in `rea.rs` | none | PLANNED |
| M3 | WebUI Buttons, 0-Diff Parity & Node.js Tests | Dashboard buttons/views verification, 0-diff sync, WiX offline assets, and Node.js native test suite (`dashboard/tests/*.test.mjs`) | none | PLANNED |
| M4 | Full Security Audit & Cargo Test Pass | Workspace audit, fixing any crate build/test issues, `cargo test --workspace` 100% pass, RAPTOR security scan | M1, M2, M3 | PLANNED |
| M5 | Final Milestone: E2E Test Suite & Hardening | Phase 1: 100% pass of Tiers 1-4 E2E tests (from `TEST_READY.md`). Phase 2: Tier 5 adversarial coverage hardening with Challengers | M4, E2E Track | PLANNED |
| M6 | Release Packaging, WDSI Submission & Sync | Windows MSI, Authenticode signing, WDSI submission, GitHub Release sync, Linux packages, Docker image, and service lifecycle verification | M5 | PLANNED |
| E2E | E2E Testing Track | Requirement-driven opaque-box test infrastructure and Tiers 1-4 test suite; publishes `TEST_READY.md` | none | DONE |

## Interface Contracts
### `osoosi-core::killchain` ↔ `osoosi-runtime::tarpit`
- `is_protected_system_or_security_process(pid: u32, exe_basename: &str) -> bool`:
  - Returns `true` for all core OS processes, desktop shell, search, and developer toolchains (`python.exe`, `python3.exe`, `cargo.exe`, `rustc.exe`, `node.exe`, `git.exe`, `code.exe`).
  - Thread freeze and tarpit actions abort immediately if this function returns `true`.

### `osoosi-core::killchain` ↔ Kernel Driver & eBPF
- Windows IOCTL `IOCTL_OSOOSI_ADD_BLOCKED_PATH`:
  - Driver evaluates `OsoosiIsCriticalSystemImage`. If image is in `g_ProtectedImages`, returns `STATUS_ACCESS_DENIED (0xC0000022)` and rejects block rule.
- Linux eBPF LSM `lsm/bprm_check_security`:
  - Probe evaluates `is_critical_linux_binary`. Critical binaries (`systemd`, `dbus-daemon`, `sshd`, `python3`, `cargo`, `node`, `init`) bypass block map.
- Linux eBPF LSM `osoosi_socket_connect`:
  - In lockdown mode, permits loopback (`127.0.0.0/8`, `::1`), management port 3030, DNS (port 53), and DHCP (ports 67/68).

### `osoosi-core::rea` ↔ `osoosi-model` / `magika`
- `detect_target_kind_tiered(path: Option<&Path>, bytes: &[u8], magika: Option<&mut magika::Session>) -> ReaTargetKind`:
  - Tier 1: Outer container envelope classification via Magika + magic bytes.
  - Tier 2: Structural PE/ELF provenance. For PE, checks `pe.header.optional_header.and_then(|o| *o.data_directories.get_clr_runtime_header())`.
  - If `virtual_address == 0 || size == 0`: binary is native PE. Check for Rust (`.dep-v0`, `rustc`), Go (`\xff Go buildinf:`), or native. Never fall back to raw BSJB scan.
  - If `virtual_address > 0`: engage .NET parser.
- `metadata["magika"]`:
  - Maps `label`, `mime_type`, `group`, `description`, `confidence`.

### `osoosi-dashboard` ↔ `dashboard/src/app.js`
- 158 Axum REST endpoints on `127.0.0.1:3030`.
- Authentication via session cookie or `X-API-Key` with constant-time token comparison.
- Responses return structured JSON; error states return `{ "success": false, "error": "..." }`.

## Code Layout
- `crates/osoosi-core/src/`:
  - `killchain.rs`: Multi-stage killchain correlation, network isolation, process freeze/unfreeze, dead-man's watchdog.
  - `rea.rs`: 2-Tier classification pipeline, bytecode decompilers, autonomous sweep, YARA synthesis.
  - `remediation.rs`: Process tree termination, session shielding, administrative protection.
  - `blocking_manager.rs`: Path blocking, executable quarantine.
  - `firewall.rs`: Host firewall isolation rules.
  - `lib.rs`: Orchestrator boot, subsystem lifecycle, quarantine event wiring.
- `crates/osoosi-runtime/src/`:
  - `tarpit.rs`: Active process and thread tarpit, protected process checks.
  - `kernel_driver.rs`: User-mode communication with Ring-0 Windows driver and Linux eBPF.
- `crates/osoosi-types/src/`:
  - `utils.rs`: Universal protected OS desktop and shell binary matrix.
- `crates/osoosi-dashboard/src/`:
  - `lib.rs`: Axum SIEM server, REST API endpoints, WebAuthn, Killchain, REA, Siquery handlers.
- `driver/windows/src/`:
  - `osoosi_driver.c`: Ring-0 process creation notify routine and `g_ProtectedImages`.
- `ebpf/src/`:
  - `osoosi_probe.bpf.c`: Linux LSM execution and socket connect hooks.
- `dashboard/`:
  - `src/`: WebUI source (`index.html`, `app.js`, `style.css`, assets).
  - `dist/`: Production distribution mirroring `src/` (`0 diff` parity).
  - `tests/`: Native Node.js test suite (`*.test.mjs`).
- `scripts/`:
  - `build_and_submit.ps1`: Release build, Authenticode signing, WiX MSI, WDSI submission, PR ship.
  - `submit_to_wdsi.py`: Microsoft Security Intelligence submission.
  - `update_github_release_msi.py`: GitHub Release and SLSA provenance sync.
  - `solo_pr_ship.ps1`: Automated maintainer PR workflow.
- `packaging/linux/`:
  - `build_packages.sh`: Linux `.deb`, `.rpm`, `.tar.gz` builder.
- `wix/`:
  - `OshoosiClaw.wxs`: Windows Installer WiX manifest.
- `Dockerfile`:
  - Multi-stage hardened container definition.
