---
description: Enforce strict PATH and environment variable immutability; ban overwriting PATH across WiX, PowerShell, and Rust.
trigger: always_on
---

# Environment Safety & PATH Immutability Protocol

1. **Absolute PATH Protection**:
   - The user's system and user `PATH` environment variables are critical system infrastructure.
   - Any operation that overwrites, resets, truncates, or deletes `PATH` is strictly prohibited.

2. **WiX MSI Packaging Guardrails**:
   - In `wix/*.wxs`, `<Environment Id="PATH" ...>` MUST strictly use `Permanent="yes"`.
   - Never set `Permanent="no"` on shared or system environment variables.
   - Use `Part="last"` to ensure append-only behavior.

3. **PowerShell & Shell Scripts**:
   - When updating `$env:PATH` in scripts, always preserve existing paths: `$env:PATH = "$targetDir;$env:PATH"`.
   - Never overwrite persistent registry values (`HKLM:\System\CurrentControlSet\Control\Session Manager\Environment` or `HKCU:\Environment`) without explicit pre-read concatenation.

4. **Runtime Code Invariant**:
   - Core binaries (`osoosi.exe`, `osoosi-cli`, driver) must never persist registry modifications to system environment variables.
