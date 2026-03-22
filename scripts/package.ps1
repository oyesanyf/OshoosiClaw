# Build and package OpenỌ̀ṣọ́ọ̀sì for deployment to another computer.
# Creates a 'deploy/' folder with all required binaries, configs, and assets.

$ErrorActionPreference = "Continue" # Don't stop on missing optional DLLs
$ProjectRoot = Get-Item "."
$DeployDir = Join-Path $ProjectRoot "deploy"

# 1. Build release binaries
Write-Host "--- Step 1: Building Release Binaries ---" -ForegroundColor Cyan
cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit $LASTEXITCODE }

# 2. Prepare deployment folder
Write-Host "--- Step 2: Preparing Deployment Folder ---" -ForegroundColor Cyan
if (Test-Path $DeployDir) { Remove-Item $DeployDir -Recurse -Force }
New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DeployDir "config") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DeployDir "yara") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DeployDir "models") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DeployDir "logs") -Force | Out-Null

# 3. Copy binaries
Write-Host "--- Step 3: Copying Binaries ---" -ForegroundColor Cyan
Copy-Item "target\release\osoosi.exe" -Destination $DeployDir -Force
Copy-Item "target\release\test-peer.exe" -Destination $DeployDir -Force

# 4. Copy ONNX Runtime DLLs (required for ML/Magika)
Write-Host "--- Step 4: Collecting Native Dependencies ---" -ForegroundColor Cyan
$OrtCache = Join-Path $env:LOCALAPPDATA "ort.pyke.io\dfbin\x86_64-pc-windows-msvc"
if (Test-Path $OrtCache) {
    $OrtDlls = Get-ChildItem -Path $OrtCache -Recurse -Filter "onnxruntime*.dll" -ErrorAction SilentlyContinue
    foreach ($dll in $OrtDlls) {
        Copy-Item $dll.FullName -Destination $DeployDir -Force
        Write-Host "   -> Added $($dll.Name)" -ForegroundColor Gray
    }
} else {
    Write-Host "   ! ONNX Runtime cache not found. If ONNX fails on the target machine, install VC++ Redistributable or copy DLLs manually." -ForegroundColor Yellow
}

# 5. Copy configuration and assets
Write-Host "--- Step 5: Adding Assets and Configs ---" -ForegroundColor Cyan
if (Test-Path "osoosi.toml") {
    Copy-Item "osoosi.toml" -Destination $DeployDir -Force
} elseif (Test-Path "osoosi.toml.example") {
    Copy-Item "osoosi.toml.example" -Destination (Join-Path $DeployDir "osoosi.toml") -Force
}

if (Test-Path "config") {
    Copy-Item "config\*" -Destination (Join-Path $DeployDir "config") -Recurse -Force
}

# 6. Copy EDR Dependencies (Sysmon)
Write-Host "--- Step 6: Including Sysmon for EDR ---" -ForegroundColor Cyan
if (Test-Path "Sysmon64.exe") {
    Copy-Item "Sysmon64.exe" -Destination $DeployDir -Force
}
if (Test-Path "sysmonconfig-export.xml") {
    Copy-Item "sysmonconfig-export.xml" -Destination $DeployDir -Force
}

# 7. Copy UI assets (dist folder)
if (Test-Path "dist") {
    Copy-Item "dist\*" -Destination (Join-Path $DeployDir "dist") -Recurse -Force -ErrorAction SilentlyContinue
}

# 8. Create a handy installation script for the target machine
$InstallScript = @"
# OpenỌ̀ṣọ́ọ̀sì Target-Side Installation Helper
# 1. Install/Update Sysmon
if (Test-Path "Sysmon64.exe") {
    echo "Installing Sysmon with security configuration..."
    .\Sysmon64.exe -i sysmonconfig-export.xml -accepteula
}
# 2. Grant permissions
echo "Ensuring administrative permissions..."
.\osoosi.exe grant-access
echo "Deployment complete. Start the agent with: .\osoosi.exe start"
"@
$InstallScript | Out-File (Join-Path $DeployDir "install.ps1") -Encoding utf8

Write-Host "`n====================================================" -ForegroundColor Green
Write-Host " Deployment Package Ready: $DeployDir" -ForegroundColor Green
Write-Host " Zip the 'deploy' folder and run on the target machine." -ForegroundColor Yellow
Write-Host "====================================================`n" -ForegroundColor Green
