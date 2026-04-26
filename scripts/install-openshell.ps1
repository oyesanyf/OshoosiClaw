param(
    [ValidateSet("linux-x64", "linux-arm64", "macos-arm64")]
    [string]$Flavor = "linux-x64",
    [string]$Version = "v0.0.36"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $repoRoot "tools\openshell"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

$asset = switch ($Flavor) {
    "linux-x64" { "openshell-x86_64-unknown-linux-musl.tar.gz" }
    "linux-arm64" { "openshell-aarch64-unknown-linux-musl.tar.gz" }
    "macos-arm64" { "openshell-aarch64-apple-darwin.tar.gz" }
}

$base = "https://github.com/NVIDIA/OpenShell/releases/download/$Version"
$archive = Join-Path $dest $asset
$checksums = Join-Path $dest "openshell-checksums-sha256.txt"

Write-Host "Downloading OpenShell $Version $Flavor..."
Invoke-WebRequest -Uri "$base/$asset" -OutFile $archive
Invoke-WebRequest -Uri "$base/openshell-checksums-sha256.txt" -OutFile $checksums

Write-Host "Saved:"
Write-Host "  $archive"
Write-Host "  $checksums"
Write-Host ""
Write-Host "Note: NVIDIA OpenShell $Version does not publish a native Windows .exe."
Write-Host "For Windows host Oshoosi, place a compatible openshell.exe at tools\openshell\openshell.exe"
Write-Host "or set OPENSHELL_CLI_PATH. Linux/macOS archives are intended for those runtimes or WSL."
