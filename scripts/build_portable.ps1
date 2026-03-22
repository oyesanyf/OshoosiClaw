# Build a self-contained portable Windows executable.
# Copies ONNX Runtime DLLs (ort) and other required binaries next to the exe.
# Run from project root: .\scripts\build_portable.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $ProjectRoot

Write-Host "Building release..." -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$TargetDir = Join-Path $ProjectRoot "target\release"
$OrtCache = Join-Path $env:LOCALAPPDATA "ort.pyke.io\dfbin\x86_64-pc-windows-msvc"

if (-not (Test-Path $OrtCache)) {
    Write-Host "ORT cache not found at $OrtCache - exe may need ONNX Runtime DLLs on target machine." -ForegroundColor Yellow
    exit 0
}

# Find onnxruntime.dll in the ort cache (structure: dfbin\<target>\<hash>\...)
$OrtDlls = Get-ChildItem -Path $OrtCache -Recurse -Filter "onnxruntime*.dll" -ErrorAction SilentlyContinue
if ($OrtDlls.Count -eq 0) {
    Write-Host "No ONNX Runtime DLLs found in ort cache. Exe may fail on machines without ort." -ForegroundColor Yellow
    exit 0
}

foreach ($dll in $OrtDlls) {
    $dest = Join-Path $TargetDir $dll.Name
    Copy-Item $dll.FullName -Destination $dest -Force
    Write-Host "Copied $($dll.Name) to target\release\" -ForegroundColor Green
}

Write-Host "`nPortable build complete. Copy the entire target\release folder (or at least osoosi-cli.exe + *.dll) to run on any Windows PC." -ForegroundColor Green
