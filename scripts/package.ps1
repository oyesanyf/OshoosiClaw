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
New-Item -ItemType Directory -Path (Join-Path $DeployDir "rules") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DeployDir "traps") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DeployDir "logs") -Force | Out-Null

# 3. Copy binaries
Write-Host "--- Step 3: Copying Binaries ---" -ForegroundColor Cyan
$BinaryPath = "target\release\osoosi.exe"
if (-not (Test-Path $BinaryPath)) {
    $BinaryPath = "target\x86_64-pc-windows-msvc\release\osoosi.exe"
}
Copy-Item $BinaryPath -Destination $DeployDir -Force

$TestPeerPath = "target\release\test-peer.exe"
if (-not (Test-Path $TestPeerPath)) {
    $TestPeerPath = "target\x86_64-pc-windows-msvc\release\test-peer.exe"
}
if (Test-Path $TestPeerPath) {
    Copy-Item $TestPeerPath -Destination $DeployDir -Force
}

# Copy Injection DLL and DirectML
if (Test-Path "osoosi_inject.dll") {
    Copy-Item "osoosi_inject.dll" -Destination $DeployDir -Force
}
if (Test-Path "DirectML.dll") {
    Copy-Item "DirectML.dll" -Destination $DeployDir -Force
}

# 4. Copy ONNX Runtime DLLs (required for ML/Magika)
Write-Host "--- Step 4: Collecting Native Dependencies ---" -ForegroundColor Cyan
$OrtCache = Join-Path $env:LOCALAPPDATA "ort.pyke.io\dfbin\x86_64-pc-windows-msvc"
if (Test-Path $OrtCache) {
    $OrtDlls = Get-ChildItem -Path $OrtCache -Recurse -Filter "onnxruntime*.dll" -ErrorAction SilentlyContinue
    foreach ($dll in $OrtDlls) {
        Copy-Item $dll.FullName -Destination $DeployDir -Force
        Write-Host "   -> Added $($dll.Name)" -ForegroundColor Gray
    }
} elseif (Test-Path "onnxruntime.dll") {
    Copy-Item "onnxruntime.dll" -Destination $DeployDir -Force
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
if (Test-Path "yara") {
    Copy-Item "yara\*" -Destination (Join-Path $DeployDir "yara") -Recurse -Force
}
if (Test-Path "models") {
    Copy-Item "models\*" -Destination (Join-Path $DeployDir "models") -Recurse -Force
}
if (Test-Path "rules") {
    Copy-Item "rules\*" -Destination (Join-Path $DeployDir "rules") -Recurse -Force
}
if (Test-Path "traps") {
    Copy-Item "traps\*" -Destination (Join-Path $DeployDir "traps") -Recurse -Force
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
if (Test-Path "dashboard\dist") {
    Copy-Item "dashboard\dist\*" -Destination (Join-Path $DeployDir "dist") -Recurse -Force -ErrorAction SilentlyContinue
} elseif (Test-Path "dist") {
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
# 2. Grant permissions & Configure Firewall
echo "Ensuring administrative permissions and configuring firewall..."
.\osoosi.exe grant-access
netsh advfirewall firewall add rule name="Oshoosi Mesh TCP" dir=in action=allow protocol=TCP localport=4001
netsh advfirewall firewall add rule name="Oshoosi Mesh UDP" dir=in action=allow protocol=UDP localport=4001
netsh advfirewall firewall add rule name="Oshoosi mDNS UDP" dir=in action=allow protocol=UDP localport=5353
echo "Deployment complete. Start the agent with: .\osoosi.exe start"
"@
$InstallScript | Out-File (Join-Path $DeployDir "install.ps1") -Encoding utf8

Write-Host "`n====================================================" -ForegroundColor Green
Write-Host " Deployment Package Ready: $DeployDir" -ForegroundColor Green
Write-Host " Zip the 'deploy' folder and run on the target machine." -ForegroundColor Yellow
Write-Host "====================================================`n" -ForegroundColor Green
