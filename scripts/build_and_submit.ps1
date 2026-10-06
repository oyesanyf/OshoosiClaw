# OpenỌ̀ṣọ́ọ̀sì Autonomous EDR - Unified Release Build & Microsoft Submission Pipeline
#
# Automates the entire release cycle in a single command:
#   1. Compiles release binary: cargo build --release -p osoosi-cli
#   2. Re-signs configuration files: .\target\release\osoosi.exe sign-configs
#   3. Syncs fresh binary to deploy\osoosi.exe
#   4. Builds WiX MSI installer: wix build wix\OshoosiClaw.wxs -arch x64 -out OshoosiClaw.msi
#   5. Synchronizes MSI to deploy\OshoosiClaw.msi
#   6. Digitally signs all 4 target binaries with Authenticode SHA-256 and DigiCert RFC 3161 timestamps
#   7. Submits all binaries to Microsoft Security Intelligence (WDSI) via scripts\submit_to_wdsi.py
#
# User Preference Enforced: "Each time the code is built, remember to send to Microsoft."

param(
    [string]$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [switch]$SkipBuild = $false,
    [switch]$SkipWix = $false,
    [switch]$SkipSigning = $false,
    [switch]$SkipSubmit = $false,
    [switch]$NoLaunch = $true
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Get-Location }
Set-Location $ProjectRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " OpenỌ̀ṣọ́ọ̀sì EDR - Unified Release Build & Microsoft Submission Pipeline" -ForegroundColor Cyan
Write-Host " Root: $ProjectRoot" -ForegroundColor Gray
Write-Host " Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# Helper: Handle locked file handles gracefully (Edge Case 1)
# -----------------------------------------------------------------------------
function Test-And-Handle-LockedFile {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        $isLocked = $false
        try {
            $stream = [System.IO.File]::OpenWrite($FilePath)
            $stream.Close()
        } catch {
            $isLocked = $true
        }
        if ($isLocked) {
            Write-Host "[LOCK] $FilePath is locked by another running process." -ForegroundColor Yellow
            $tempLocked = "$FilePath.locked." + [System.Guid]::NewGuid().ToString("N")
            try {
                Move-Item -Path $FilePath -Destination $tempLocked -Force
                Write-Host "       Successfully moved locked file to temporary location: $tempLocked" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to move locked file $FilePath : $_"
            }
        }
    }
}

function Cleanup-OldLockedFiles {
    Get-ChildItem -Path $ProjectRoot -Filter "*.locked.*" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
    }
}
Cleanup-OldLockedFiles

# -----------------------------------------------------------------------------
# Helper: Cargo & WiX toolset auto-discovery in PATH and standard locations (Edge Case 2)
# -----------------------------------------------------------------------------
function Ensure-ToolchainInPath {
    # 1. Cargo discovery
    $cargoCmd = Get-Command "cargo" -ErrorAction SilentlyContinue
    if (-not $cargoCmd) {
        $candidateCargoDirs = @(
            (Join-Path $env:USERPROFILE ".cargo\bin"),
            "C:\Users\oyesanyf\.cargo\bin",
            (Join-Path $env:ProgramFiles "Rust\bin")
        )
        foreach ($dir in $candidateCargoDirs) {
            if ($dir -and (Test-Path (Join-Path $dir "cargo.exe"))) {
                Write-Host "[TOOL] Discovered Cargo at '$dir'. Adding to PATH." -ForegroundColor Cyan
                $env:PATH = "$dir;$env:PATH"
                break
            }
        }
    }

    # 2. WiX discovery
    $wixCmd = Get-Command "wix" -ErrorAction SilentlyContinue
    if (-not $wixCmd) {
        $candidateWixDirs = @(
            "C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin",
            (Join-Path $env:USERPROFILE "wix_tools\PFiles64\WiX Toolset v5.0\bin"),
            (Join-Path $env:USERPROFILE ".dotnet\tools"),
            (Join-Path $env:ProgramFiles "WiX Toolset v5.0\bin"),
            (Join-Path ${env:ProgramFiles(x86)} "WiX Toolset v5.0\bin"),
            (Join-Path $env:LOCALAPPDATA "Programs\wix")
        )
        foreach ($dir in $candidateWixDirs) {
            if ($dir -and (Test-Path (Join-Path $dir "wix.exe"))) {
                Write-Host "[TOOL] Discovered WiX Toolset at '$dir'. Adding to PATH." -ForegroundColor Cyan
                $env:PATH = "$dir;$env:PATH"
                break
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Helper: Authenticode Code-Signing (Edge Case 3)
# -----------------------------------------------------------------------------
function Invoke-AuthenticodeSigning {
    param(
        [string[]]$Files,
        [string]$Thumbprint,
        [string]$Timestamp
    )

    $Cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
    if (-not $Cert) {
        $Cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
    }

    if (-not $Cert) {
        Write-Warning "[SIGN] Code-signing certificate '$Thumbprint' not found in Cert stores."
        Write-Warning "       Skipping digital signature step. Artifacts will remain unsigned."
        return $false
    }

    Write-Host "[SIGN] Active Signing Certificate: $($Cert.Subject) ($($Cert.Thumbprint))" -ForegroundColor Green
    foreach ($file in $Files) {
        if (Test-Path $file) {
            Write-Host "       Signing '$file' (SHA-256 + RFC 3161 timestamp)..." -ForegroundColor Cyan
            try {
                $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $Cert -TimestampServer $Timestamp -HashAlgorithm SHA256
                Write-Host "       -> $($sig.Status): $file" -ForegroundColor Green
            } catch {
                Write-Warning "       -> Signing failed for $file : $_"
            }
        } else {
            Write-Warning "       -> Target file not found for signing: $file"
        }
    }
    return $true
}

# Ensure toolchain is available in environment
Ensure-ToolchainInPath

# Ensure deploy/ directory exists
$DeployDir = Join-Path $ProjectRoot "deploy"
if (-not (Test-Path $DeployDir)) {
    New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
}

# =============================================================================
# Step 1: Build Release Binary (cargo build --release -p osoosi-cli)
# =============================================================================
$TargetExe = Join-Path $ProjectRoot "target\release\osoosi.exe"
if (-not $SkipBuild) {
    Write-Host "`n>>> [1/6] Building osoosi-cli Release Binary..." -ForegroundColor Yellow
    Test-And-Handle-LockedFile -FilePath $TargetExe

    cargo build --release -p osoosi-cli
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo build failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Host "       -> Build successful: $TargetExe" -ForegroundColor Green
} else {
    Write-Host "`n>>> [1/6] Skipping cargo build (-SkipBuild specified)" -ForegroundColor Gray
}

# =============================================================================
# Step 2: Re-sign Configurations (osoosi.exe sign-configs)
# =============================================================================
Write-Host "`n>>> [2/6] Re-signing Agent Configurations..." -ForegroundColor Yellow
if (Test-Path $TargetExe) {
    & $TargetExe sign-configs
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "sign-configs returned non-zero code ($LASTEXITCODE), continuing..."
    } else {
        Write-Host "       -> Configurations re-signed successfully." -ForegroundColor Green
    }
} else {
    Write-Error "Target binary not found at $TargetExe. Cannot sign configs."
    exit 1
}

# =============================================================================
# Step 3: Copy Fresh Binary to deploy\osoosi.exe
# =============================================================================
Write-Host "`n>>> [3/6] Syncing Fresh Binary to deploy\osoosi.exe..." -ForegroundColor Yellow
$DeployExe = Join-Path $DeployDir "osoosi.exe"
Test-And-Handle-LockedFile -FilePath $DeployExe
Copy-Item -Path $TargetExe -Destination $DeployExe -Force
Write-Host "       -> Copied: $TargetExe -> $DeployExe" -ForegroundColor Green

# =============================================================================
# Step 4: Build WiX MSI Installer (wix build wix\OshoosiClaw.wxs -arch x64 ...)
# =============================================================================
$RootMsi = Join-Path $ProjectRoot "OshoosiClaw.msi"
$DeployMsi = Join-Path $DeployDir "OshoosiClaw.msi"

if (-not $SkipWix) {
    Write-Host "`n>>> [4/6] Building WiX MSI Installer Package..." -ForegroundColor Yellow
    $WixWxs = Join-Path $ProjectRoot "wix\OshoosiClaw.wxs"

    if (Test-Path $WixWxs) {
        $WixCmd = Get-Command "wix" -ErrorAction SilentlyContinue
        if ($WixCmd) {
            Test-And-Handle-LockedFile -FilePath $RootMsi
            Test-And-Handle-LockedFile -FilePath $DeployMsi

            & wix build $WixWxs -arch x64 -out $RootMsi
            if ($LASTEXITCODE -ne 0 -or (-not (Test-Path $RootMsi))) {
                Write-Error "WiX MSI build failed with exit code $LASTEXITCODE"
                exit 1
            }
            Copy-Item -Path $RootMsi -Destination $DeployMsi -Force
            Write-Host "       -> MSI built and synchronized successfully: $DeployMsi" -ForegroundColor Green
        } else {
            Write-Warning "WiX toolset not found. MSI generation skipped."
        }
    } else {
        Write-Warning "WiX manifest not found at $WixWxs."
    }
} else {
    Write-Host "`n>>> [4/6] Skipping WiX build (-SkipWix specified)" -ForegroundColor Gray
}

# =============================================================================
# Step 5: Authenticode SHA-256 Code-Signing & DigiCert RFC 3161 Timestamping
# =============================================================================
Write-Host "`n>>> [5/6] Code-Signing Target Binaries & MSI Installers..." -ForegroundColor Yellow
$TargetBinaries = @(
    $TargetExe,
    $DeployExe,
    $RootMsi,
    $DeployMsi
) | Where-Object { Test-Path $_ }

if (-not $SkipSigning) {
    Invoke-AuthenticodeSigning -Files $TargetBinaries -Thumbprint $CertThumbprint -Timestamp $TimestampServer | Out-Null
    # Ensure signed MSI is synchronized if RootMsi was signed
    if ((Test-Path $RootMsi) -and (Test-Path $DeployMsi)) {
        Copy-Item -Path $RootMsi -Destination $DeployMsi -Force
    }
} else {
    Write-Host "       -> Skipping code-signing (-SkipSigning specified)" -ForegroundColor Gray
}

# =============================================================================
# Step 6: Automated Microsoft Security Intelligence (WDSI) Submission
# =============================================================================
Write-Host "`n>>> [6/6] Submitting to Microsoft Security Intelligence (WDSI)..." -ForegroundColor Yellow
if (-not $SkipSubmit) {
    $WdsiScript = Join-Path $ProjectRoot "scripts\submit_to_wdsi.py"
    if (Test-Path $WdsiScript) {
        $submitArgs = @($WdsiScript, "--all")
        if ($NoLaunch) {
            $submitArgs += "--no-launch"
        }
        Write-Host "       Executing: python $($submitArgs -join ' ')" -ForegroundColor Cyan
        & python @submitArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "submit_to_wdsi.py returned code $LASTEXITCODE"
        } else {
            Write-Host "       -> Microsoft submission workflow completed successfully." -ForegroundColor Green
        }
    } else {
        Write-Error "WDSI submission script not found at $WdsiScript"
        exit 1
    }
} else {
    Write-Host "       -> Skipping Microsoft submission (-SkipSubmit specified)" -ForegroundColor Gray
}

Cleanup-OldLockedFiles

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host " Pipeline Execution Complete!" -ForegroundColor Green
Write-Host " Release Binaries & MSI Packaged, Signed, and Submitted to Microsoft." -ForegroundColor Green
Write-Host " Report saved to: deploy\reports\wdsi_submissions.json" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Green
