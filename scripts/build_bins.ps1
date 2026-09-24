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

# Copy main executables
$Binaries = @("osoosi.exe", "osoosi-auditor.exe", "test-peer.exe")
foreach ($bin in $Binaries) {
    $binPath = Join-Path $TargetDir $bin
    if (Test-Path $binPath) {
        Copy-Item $binPath -Destination (Join-Path $BinsDir $bin) -Force
        Write-Host "Copied $bin" -ForegroundColor Green
    }
}
# Backward compatibility alias
if (Test-Path (Join-Path $BinsDir "osoosi.exe")) {
    Copy-Item (Join-Path $BinsDir "osoosi.exe") -Destination (Join-Path $BinsDir "osoosi-cli.exe") -Force
}

# Copy native runtime dependencies (ONNX Runtime, DirectML, inject DLL)
$RootOrt = Join-Path $ProjectRoot "onnxruntime.dll"
if (Test-Path $RootOrt) {
    Copy-Item $RootOrt -Destination (Join-Path $BinsDir "onnxruntime.dll") -Force
    Write-Host "Copied onnxruntime.dll (from workspace root)" -ForegroundColor Green
} elseif (Test-Path (Join-Path $TargetDir "onnxruntime.dll")) {
    Copy-Item (Join-Path $TargetDir "onnxruntime.dll") -Destination (Join-Path $BinsDir "onnxruntime.dll") -Force
    Write-Host "Copied onnxruntime.dll (from target\release)" -ForegroundColor Green
} else {
    $OrtCache = Join-Path $env:LOCALAPPDATA "ort.pyke.io\dfbin\x86_64-pc-windows-msvc"
    if (Test-Path $OrtCache) {
        $OrtDlls = Get-ChildItem -Path $OrtCache -Recurse -Filter "onnxruntime*.dll" -ErrorAction SilentlyContinue
        foreach ($dll in $OrtDlls) {
            Copy-Item $dll.FullName -Destination (Join-Path $BinsDir $dll.Name) -Force
            Write-Host "Copied $($dll.Name)" -ForegroundColor Green
        }
    } else {
        Write-Host "ONNX Runtime DLL not found - ML model may not work without ort DLLs" -ForegroundColor Yellow
    }
}

if (Test-Path (Join-Path $ProjectRoot "DirectML.dll")) {
    Copy-Item (Join-Path $ProjectRoot "DirectML.dll") -Destination (Join-Path $BinsDir "DirectML.dll") -Force
    Write-Host "Copied DirectML.dll" -ForegroundColor Green
}
if (Test-Path (Join-Path $ProjectRoot "osoosi_inject.dll")) {
    Copy-Item (Join-Path $ProjectRoot "osoosi_inject.dll") -Destination (Join-Path $BinsDir "osoosi_inject.dll") -Force
    Write-Host "Copied osoosi_inject.dll" -ForegroundColor Green
}
if (Test-Path (Join-Path $ProjectRoot "wintun.dll")) {
    Copy-Item (Join-Path $ProjectRoot "wintun.dll") -Destination (Join-Path $BinsDir "wintun.dll") -Force
    Write-Host "Copied wintun.dll" -ForegroundColor Green
}

# Copy config and assets
$ItemsToCopy = @(
    @{ Src = "config"; Dest = "config" },
    @{ Src = "rules\sigma"; Dest = "sigma" },
    @{ Src = "rules\sigma"; Dest = "rules\sigma" },
    @{ Src = "rules"; Dest = "rules" },
    @{ Src = "dashboard\dist"; Dest = "dashboard\dist" },
    @{ Src = "dashboard\dist"; Dest = "dist" },
    @{ Src = "osoosi.toml"; Dest = "osoosi.toml" },
    @{ Src = "yara"; Dest = "yara" },
    @{ Src = "traps"; Dest = "traps" }
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
        Write-Host "Copied $($item.Src) -> $($item.Dest)" -ForegroundColor Green
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
osoosi.exe start
pause
"@
$RunScript | Set-Content (Join-Path $BinsDir "run.bat") -Encoding ASCII
Write-Host "Created run.bat" -ForegroundColor Green

Write-Host "`nBuild complete. Standalone package in: $BinsDir" -ForegroundColor Cyan
Write-Host "Run: cd bins; .\osoosi.exe start" -ForegroundColor Cyan
Write-Host "Or double-click run.bat" -ForegroundColor Cyan
