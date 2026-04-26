$ErrorActionPreference = "Stop"

Write-Host "[Oshoosi] Checking WSL..."
wsl.exe --status | Out-Host

Write-Host "[Oshoosi] Installing uv and NVIDIA OpenShell inside WSL..."
wsl.exe sh -lc 'set -e; if ! command -v uv >/dev/null 2>&1; then curl -LsSf https://astral.sh/uv/install.sh | sh; fi; export PATH="$HOME/.cargo/bin:$PATH"; uv tool install --prerelease=allow openshell; openshell --version'

Write-Host ""
Write-Host "[Oshoosi] Done. The Windows agent will now detect OpenShell through:"
Write-Host "  wsl.exe openshell --version"
Write-Host ""
Write-Host "Start Oshoosi with:"
Write-Host "  .\target\release\osoosi.exe start --sandbox --sandbox-name my-agent-sandbox"
