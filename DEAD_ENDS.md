# Dead Ends Log

| Iteration | Approach Tried | Why It Failed | Files Touched |
|-----------|---------------|---------------|---------------|
| M1 Iteration 1 | Naive space-bounded substring checks (`" -c "`, `" -e "`) for inline interpreter code | Bypassed by attached syntax without spaces (`python -c"..."`, `node -e"..."`, `node --eval="..."`) | `crates/osoosi-types/src/utils.rs` |
| M1 Iteration 1 | Naive string matchers (`"evil"`, `"beacon"`, `"downloadstring"`) in production types | Violates zero-mock rule; causes false-positive immunity revocation on legitimate test scripts | `crates/osoosi-types/src/utils.rs` |
| M1 Iteration 1 | Adding LOLBins (`powershell.exe`, `pwsh.exe`, `cmd.exe`) to Ring-0 `g_ProtectedImages` | Direct contradiction with user-space LOLBin policy; causes driver to refuse IOCTL blocking with `STATUS_ACCESS_DENIED` | `driver/windows/src/osoosi_driver.c` |
| M1 Iteration 1 | Iterating over arbitrary trailing CLI arguments in `is_administrative_or_ssh_session` | Malware can append dummy args (`mimikatz.exe git`) to evade `kill_process_tree` | `crates/osoosi-core/src/remediation.rs` |
| M1 Iteration 1 | Stripping stem from unparsed command-line string in `utils.rs:1303` | Legitimate binaries with CLI flags (`cargo.exe build`, `explorer.exe /n`) fail stem match and lose immunity | `crates/osoosi-types/src/utils.rs` |
| M1 Iteration 1 | Shared hardcoded database path `database/killchain_state.json` without test isolation | Concurrent or sequential cargo test runs suffer race conditions on disk | `crates/osoosi-core/src/killchain.rs` |
| M1 Iteration 2 | Exporting `is_protected_process` without exporting `is_critical_system_process` | Downstream crates (`osoosi-telemetry::canary.rs:863`) call `is_critical_system_process`, causing compilation error E0425 across workspace | `crates/osoosi-types/src/utils.rs` |
| M1 Iteration 2 | Running pre-compiled test binaries instead of building from clean source | Masks compiler breaks in downstream crates, failing independent forensic verification | `worker_m1_r2/handoff.md` |
| M1 Iteration 2 | Informational `println!` without hard assertions in challenger test | Tests do not fail if vulnerability regresses; must use hard `assert!(!is_shielded)` | `crates/osoosi-core/tests/challenger_m1_remediation_tests.rs` |
