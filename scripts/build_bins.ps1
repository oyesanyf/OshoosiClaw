# Build OpenỌ̀ṣọ́ọ̀sì to bins/ folder with all dependencies for standalone run.
# Run from project root: .\scripts\build_bins.ps1
# Then: cd bins; .\osoosi-cli.exe start

$ErrorActionPreference = "Stop"
$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Get-Location }
if (-not (Test-Path (Join-Path $ProjectRoot "Cargo.toml"))) {
    $ProjectRoot = Get-Location
}
Set-Location $ProjectRoot

$BinsDir = Join-Path $ProjectRoot "bins"
$TargetDir = Join-Path $ProjectRoot "target\release"

Write-Host "Building release (multithreaded)..." -ForegroundColor Cyan
cargo build --release -p osoosi-cli
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Create bins folder
if (Test-Path $BinsDir) { Remove-Item $BinsDir -Recurse -Force }
New-Item -ItemType Directory -Path $BinsDir -Force | Out-Null

# Copy main executable
$ExeName = "osoosi-cli.exe"
Copy-Item (Join-Path $TargetDir $ExeName) -Destination (Join-Path $BinsDir $ExeName) -Force
Write-Host "Copied $ExeName" -ForegroundColor Green

# Copy ONNX Runtime DLLs (required for malware ML model)
$OrtCache = Join-Path $env:LOCALAPPDATA "ort.pyke.io\dfbin\x86_64-pc-windows-msvc"
if (Test-Path $OrtCache) {
    $OrtDlls = Get-ChildItem -Path $OrtCache -Recurse -Filter "onnxruntime*.dll" -ErrorAction SilentlyContinue
    foreach ($dll in $OrtDlls) {
        Copy-Item $dll.FullName -Destination (Join-Path $BinsDir $dll.Name) -Force
        Write-Host "Copied $($dll.Name)" -ForegroundColor Green
    }
} else {
    Write-Host "ONNX Runtime cache not found - ML model may not work without ort DLLs" -ForegroundColor Yellow
}

# Copy config and assets
$ItemsToCopy = @(
    @{ Src = "config"; Dest = "config" },
    @{ Src = "sigma"; Dest = "sigma" },
    @{ Src = "dashboard\dist"; Dest = "dashboard\dist" },
    @{ Src = "osoosi.toml"; Dest = "osoosi.toml" },
    @{ Src = "yara"; Dest = "yara" }
)
foreach ($item in $ItemsToCopy) {
    $srcPath = Join-Path $ProjectRoot $item.Src
    $destPath = Join-Path $BinsDir $item.Dest
    if (Test-Path $srcPath) {
        $destParent = Split-Path $destPath -Parent
        if (-not (Test-Path $destParent)) { New-Item -ItemType Directory -Path $destParent -Force | Out-Null }
        if (Test-Path $srcPath -PathType Container) {
            Copy-Item $srcPath -Destination $destPath -Recurse -Force
        } else {
            Copy-Item $srcPath -Destination $destPath -Force
        }
        Write-Host "Copied $($item.Src)" -ForegroundColor Green
    }
}

# Create default config if missing
$ConfigDir = Join-Path $BinsDir "config"
if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
$FirewallAllowlist = Join-Path $ConfigDir "firewall_allowlist.txt"
if (-not (Test-Path $FirewallAllowlist)) {
    @"
# Firewall allowlist - programs not blocked
git.exe
com.docker.cli.exe
"@ | Set-Content $FirewallAllowlist -Encoding UTF8
    Write-Host "Created config/firewall_allowlist.txt" -ForegroundColor Green
}
$SoftwareReplacement = Join-Path $ConfigDir "software_replacement.txt"
if (-not (Test-Path $SoftwareReplacement)) {
    @"
# Software replacement: basename|source (github:owner/repo or url:https://...)
# git.exe|github:git-for-windows/git:64-bit
"@ | Set-Content $SoftwareReplacement -Encoding UTF8
    Write-Host "Created config/software_replacement.txt" -ForegroundColor Green
}

# Create logs and quarantine dirs
New-Item -ItemType Directory -Path (Join-Path $BinsDir "logs") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $BinsDir "quarantine") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $BinsDir "models") -Force | Out-Null

# Create run script
$RunScript = @"
@echo off
cd /d "%~dp0"
echo Starting OpenỌ̀ṣọ́ọ̀sì from %CD%
osoosi-cli.exe start
pause
"@
$RunScript | Set-Content (Join-Path $BinsDir "run.bat") -Encoding ASCII
Write-Host "Created run.bat" -ForegroundColor Green

Write-Host "`nBuild complete. Standalone package in: $BinsDir" -ForegroundColor Cyan
Write-Host "Run: cd bins; .\osoosi-cli.exe start" -ForegroundColor Cyan
Write-Host "Or double-click run.bat" -ForegroundColor Cyan
