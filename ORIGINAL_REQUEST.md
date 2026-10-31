## 2026-10-31T12:48:58Z

Extend OshoosiClaw's secret seal system to scan and seal environment variables across files, configure seal targets and options under the Utilities tab, and automatically unseal and restore backups when the EDR service stops, for production use in OshoosiClaw.

Working directory: d:\harfile\OshoosiClaw
Integrity mode: development

## Verification Resources
- Existing repository test suites (`cargo test -p osoosi-core`, `cargo test -p osoosi-dashboard`, `cargo test -p osoosi-cli`)
- CLI environment gateway test command (`osoosi.exe env-gateway test`)
- Windows and Linux packaging scripts (`scripts/build_and_submit.ps1`, `packaging/linux/build_packages.sh`)
- Solo PR shipping automation (`scripts/solo_pr_ship.ps1`)

## Requirements

### R1. Multi-File Environment Scanning and Sealing (`crates/osoosi-core`, `crates/osoosi-cli`)
Extend the secret seal system (`ProtectedEnvBackupVault` and CLI commands) to discover and scan environment files across the workspace root, immediate subdirectories (matching standard files like `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`), and custom user-specified paths. Back up each file's original contents into `ProtectedVaultPayload` using ChaCha20Poly1305 encryption and BLAKE3 MAC verification, replace selected secret values with `OSHOOSI_STANDIN_*` tokens upon sealing, and restore all files to their exact original contents on revert.

### R2. Utilities Configuration and Management REST API (`crates/osoosi-dashboard`)
Implement persistent seal configuration (`EnvSealConfig`, stored in `database/env_seal_config.json` or `osoosi.toml`) and REST API endpoints (`/api/env-gateway/status`, `/api/env-gateway/config`, `/api/env-gateway/scan-files`, `/api/env-gateway/seal`, `/api/env-gateway/revert`, `/api/env-gateway/test`) allowing users to query status, configure target files/directories, and select/deselect which environment variables to seal, enforcing immutable Zero-Touch protection on `Path`/`PATH`, `JAVA_HOME`, `TEMP`, `TMP`, and system variables.

### R3. WebUI Utilities & Models Configuration Interface (`dashboard/src/`, `dashboard/dist/`)
Add an interactive "Environment Gateway & Secret Seal Configuration" section under the Utilities & Models view (`#utilities` / `#utilities-view`) in `dashboard/src/index.html` and `dashboard/src/app.js` with 0-diff parity to `dashboard/dist/`. Provide UI controls to manage file scanning paths, toggle environment variables to seal, trigger scan, seal, and revert operations, and run the live 4-stage Stand-in Token Verification test directly from the UI.

### R4. Mandatory Automatic Unseal on EDR Service Stop (`crates/osoosi-cli`, `crates/osoosi-core`)
Whenever the EDR service or daemon stops (`SERVICE_CONTROL_STOP` in Windows service, `osoosi stop` CLI command, `Ctrl+C` / `SIGTERM` signals, `wait_for_shutdown()`, and `EdrOrchestrator` shutdown), automatically unseal and restore all backed-up secrets from the protected vault back to:
- All sealed `.env` / environment files on disk,
- Windows User Environment (`HKCU\Environment` and `HKEY_USERS\S-1-5-21-*\Environment` + `WM_SETTINGCHANGE`),
- Process memory (`std::env`),
while strictly preserving `PATH`/`Path` and non-secret system variables untouched. Locate and revert across all active vault paths (`database/protected_env_backup.vault` in the repo root and `target/release/database/protected_env_backup.vault`) so service stop never misses the active vault due to process working directory differences.

### R5. Full-Lifecycle Verification, Packaging & Ship
Verify all unit and integration tests pass across `osoosi-core`, `osoosi-dashboard`, and `osoosi-cli`. Rebuild and Authenticode-sign Windows release binaries and MSI installer via `scripts/build_and_submit.ps1`, verify Linux packaging, and ship verified checkpoints via `scripts/solo_pr_ship.ps1`.
