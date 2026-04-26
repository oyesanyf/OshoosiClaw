# OpenShell Tool Slot

OshoosiClaw now searches this directory for NVIDIA OpenShell before falling back to
`OPENSHELL_CLI_PATH`, the persisted tool cache, and `PATH`.

Expected local paths:

- Windows native CLI, if NVIDIA publishes one later: `tools/openshell/openshell.exe`
- Windows native CLI under a bin folder: `tools/openshell/bin/openshell.exe`
- Linux/macOS CLI: `tools/openshell/openshell` or `tools/openshell/bin/openshell`

NVIDIA OpenShell v0.0.36 does not publish a native Windows `.exe` asset in the
GitHub release. The available binary artifacts are Linux and macOS builds, plus
Linux/macOS Python wheels. On Windows, use one of these options:

1. Install OpenShell in WSL/Linux. Oshoosi detects `wsl.exe openshell`
   automatically and uses it as the OpenShell command path on Windows.
2. If you obtain a Windows-compatible `openshell.exe`, place it in this folder.
3. Set `OPENSHELL_CLI_PATH` to the exact executable path.

WSL install:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.cargo/env"
uv tool install --prerelease=allow openshell
openshell --version
```

Release used for checksums and supported artifacts:
https://github.com/NVIDIA/OpenShell/releases/tag/v0.0.36
