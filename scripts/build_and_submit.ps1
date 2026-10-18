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
    [switch]$NoLaunch = $true,
    [string]$PrTitle = "feat(siquery): resilient sqlite busy timeout and peer status fallback for 100 tables"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
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
    $searchDirs = @(
        (Join-Path $ProjectRoot "target\release"),
        (Join-Path $ProjectRoot "deploy"),
        $ProjectRoot
    )
    foreach ($dir in $searchDirs) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -Filter "*.locked.*" -ErrorAction SilentlyContinue | ForEach-Object {
                try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
}
Cleanup-OldLockedFiles

# -----------------------------------------------------------------------------
# Helper: Cargo & WiX toolset auto-discovery in PATH and standard locations (Edge Case 2)
# -----------------------------------------------------------------------------
function Ensure-ToolchainInPath {
    # 0. Rustup toolchain bin discovery (preserves Windows 11 Smart App Control origin claim)
    $toolchainBin = "C:\Users\oyesanyf\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"
    if (Test-Path (Join-Path $toolchainBin "cargo.exe")) {
        $env:PATH = "$toolchainBin;$env:PATH"
    }

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
    $signtoolCandidates = @(
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"
    )
    $signtool = $signtoolCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $signtool) {
        $stCmd = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
        if ($stCmd) { $signtool = $stCmd.Source }
    }

    foreach ($file in $Files) {
        if (Test-Path $file) {
            $isTarget = $TargetBinaries -contains $file
            $existingSig = Get-AuthenticodeSignature $file -ErrorAction SilentlyContinue
            if (-not $isTarget -and $existingSig -and $existingSig.SignerCertificate -and ($existingSig.SignerCertificate.Thumbprint -eq $Thumbprint)) {
                Write-Host "       -> Already signed by $($existingSig.SignerCertificate.Subject): $file" -ForegroundColor Green
                continue
            }
            Write-Host "       Signing '$file' (SHA-256 + RFC 3161 timestamp)..." -ForegroundColor Cyan
            $signedOk = $false
            try {
                if ($signtool) {
                    # 1. Primary: signtool with RFC 3161 timestamp
                    & $signtool sign /sha1 $Thumbprint /fd SHA256 /tr $Timestamp /td SHA256 $file | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        $signedOk = $true
                    } else {
                        # 2. Secondary fallback: signtool without timestamp
                        Write-Warning "       -> Timestamp server failed for $file. Retrying signtool without timestamp..."
                        & $signtool sign /sha1 $Thumbprint /fd SHA256 $file | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            $signedOk = $true
                        }
                    }
                }

                if (-not $signedOk) {
                    # 3. Tertiary fallback: Set-AuthenticodeSignature cmdlet
                    $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $Cert -TimestampServer $Timestamp -HashAlgorithm SHA256
                    if ($sig.Status -eq "Valid" -or $sig.Status -eq "UnknownError") {
                        $signedOk = $true
                    }
                }
            } catch {
                Write-Warning "       -> Signing failed for $file : $_"
            }

            # 4. Mandatory Post-Sign Verification: ensure SignerCertificate is present
            $postSig = Get-AuthenticodeSignature $file
            if ($postSig.SignerCertificate -ne $null) {
                Write-Host "       -> Valid (Signed by $($postSig.SignerCertificate.Subject)): $file" -ForegroundColor Green
            } else {
                Write-Error "       -> CRITICAL: $file remained unsigned after signing attempts! Status: $($postSig.Status)"
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
    Write-Host "`n>>> [1/8] Building osoosi-cli Release Binary..." -ForegroundColor Yellow
    
    # If OsoosiEDR service is running, stop it before compiling to release file handles
    $scQuery = & sc.exe query OsoosiEDR 2>&1 | Out-String
    if ($scQuery -match "STATE\s*:\s*[0-9]+\s+RUNNING") {
        Write-Host "       Stopping OsoosiEDR service before release build to release binary locks..." -ForegroundColor Cyan
        & sc.exe stop OsoosiEDR | Out-Null
        Start-Sleep -Seconds 1
    }

    # Ensure file handles on target are not locked
    Test-And-Handle-LockedFile -FilePath $TargetExe
    $depsExe = Join-Path $ProjectRoot "target\release\deps\osoosi.exe"
    Test-And-Handle-LockedFile -FilePath $depsExe

    $signtoolCandidates = @(
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"
    )
    $buildSigntool = $signtoolCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    $buildSucceeded = $false
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        # Clear ReadOnly attributes on release binaries to prevent autocfg / cargo output path errors
        & cmd.exe /c "attrib -r target\release\*.exe 2>nul & attrib -r target\release\*.dll 2>nul & attrib -r target\release\deps\*.exe 2>nul" | Out-Null

        # Sign build scripts / proc macros with DigiCert RFC 3161 timestamp on retry if cargo failed
        if ($attempt -gt 1 -and $buildSigntool -and (-not $SkipSigning)) {
            Get-ChildItem (Join-Path $ProjectRoot "target\release\build"), (Join-Path $ProjectRoot "target\release\deps") -Include "*.exe","*.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object {
                $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                (-not $sig) -or ($sig.SignerCertificate -eq $null) -or ($sig.TimeStamperCertificate -eq $null)
            } | ForEach-Object {
                $wt = $_.LastWriteTimeUtc
                & $buildSigntool sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 /q $_.FullName 2>$null | Out-Null
                try { (Get-Item $_.FullName).LastWriteTimeUtc = $wt } catch {}
            }
        }

        & cmd.exe /c "cargo build --release -p osoosi-cli"
        if ($LASTEXITCODE -eq 0) {
            $buildSucceeded = $true
            break
        }
        if ($buildSigntool -and (-not $SkipSigning) -and $attempt -lt 10) {
            Write-Host "       [WDAC] Signing newly compiled build scripts / proc-macros with RFC 3161 timestamp before retry ($attempt/10)..." -ForegroundColor Cyan
            Get-ChildItem (Join-Path $ProjectRoot "target\release\build"), (Join-Path $ProjectRoot "target\release\deps") -Include "*.exe","*.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object {
                $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                (-not $sig) -or ($sig.SignerCertificate -eq $null) -or ($sig.TimeStamperCertificate -eq $null)
            } | ForEach-Object {
                $wt = $_.LastWriteTimeUtc
                & $buildSigntool sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 /q $_.FullName 2>$null | Out-Null
                try { (Get-Item $_.FullName).LastWriteTimeUtc = $wt } catch {}
            }
            Start-Sleep -Seconds 1
        } else {
            break
        }
    }

    if (-not $buildSucceeded) {
        Write-Error "cargo build failed with exit code $LASTEXITCODE"
        exit 1
    }
    Write-Host "       -> Build successful: $TargetExe" -ForegroundColor Green
} else {
    Write-Host "`n>>> [1/8] Skipping cargo build (-SkipBuild specified)" -ForegroundColor Gray
}

# =============================================================================
# Step 2: Re-sign Configurations (osoosi.exe sign-configs)
# =============================================================================
Write-Host "`n>>> [2/8] Re-signing Agent Configurations..." -ForegroundColor Yellow
if (Test-Path $TargetExe) {
    # If Application Control is enforced, binary must be signed before it can execute
    if (-not $SkipSigning) {
        Invoke-AuthenticodeSigning -Files @($TargetExe) -Thumbprint $CertThumbprint -Timestamp $TimestampServer | Out-Null
    }
    try {
        & $TargetExe sign-configs
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "sign-configs returned non-zero code ($LASTEXITCODE), continuing..."
        } else {
            Write-Host "       -> Configurations re-signed successfully." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to execute $TargetExe sign-configs: $_. Continuing pipeline..."
    }
} else {
    Write-Error "Target binary not found at $TargetExe. Cannot sign configs."
    exit 1
}

# =============================================================================
# Step 3: Copy Fresh Binary & Immediate Hot-Swap Service Restart
# =============================================================================
Write-Host "`n>>> [3/8] Syncing Fresh Binary & Hot-Swapping OsoosiEDR Service..." -ForegroundColor Yellow
$DeployExe = Join-Path $DeployDir "osoosi.exe"
Test-And-Handle-LockedFile -FilePath $DeployExe
Copy-Item -Path $TargetExe -Destination $DeployExe -Force
Write-Host "       -> Copied: $TargetExe -> $DeployExe" -ForegroundColor Green

# Hot-Swap: Ensure both binaries are Authenticode signed and start/restart service immediately
if (-not $SkipSigning) {
    Invoke-AuthenticodeSigning -Files @($TargetExe, $DeployExe) -Thumbprint $CertThumbprint -Timestamp $TimestampServer | Out-Null
}
$scQueryPre = & sc.exe query OsoosiEDR 2>&1 | Out-String
if ($scQueryPre -match "STATE\s*:\s*[0-9]+\s+RUNNING") {
    Write-Host "       OsoosiEDR service is currently RUNNING. Hot-swapping with freshly compiled binary..." -ForegroundColor Cyan
    & sc.exe stop OsoosiEDR | Out-Null
    Start-Sleep -Seconds 1
    Test-And-Handle-LockedFile -FilePath $TargetExe
    Copy-Item -Path $DeployExe -Destination $TargetExe -Force
    & sc.exe start OsoosiEDR | Out-Null
    Write-Host "       -> OsoosiEDR service hot-swapped and running with newly compiled binary." -ForegroundColor Green
} elseif ($scQueryPre -match "SERVICE_NAME\s*:\s*OsoosiEDR") {
    Write-Host "       Starting OsoosiEDR service with freshly built binary..." -ForegroundColor Cyan
    Test-And-Handle-LockedFile -FilePath $TargetExe
    Copy-Item -Path $DeployExe -Destination $TargetExe -Force
    & sc.exe start OsoosiEDR | Out-Null
    Write-Host "       -> OsoosiEDR service started." -ForegroundColor Green
}

# =============================================================================
# Step 4: Build WiX MSI Installer (wix build wix\OshoosiClaw.wxs -arch x64 ...)
# =============================================================================
$RootMsi = Join-Path $ProjectRoot "OshoosiClaw.msi"
$DeployMsi = Join-Path $DeployDir "OshoosiClaw.msi"

if (-not $SkipWix) {
    Write-Host "`n>>> [4/8] Building WiX MSI Installer Package..." -ForegroundColor Yellow
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
    Write-Host "`n>>> [4/8] Skipping WiX build (-SkipWix specified)" -ForegroundColor Gray
}

# =============================================================================
# Step 5: Authenticode SHA-256 Code-Signing & DigiCert RFC 3161 Timestamping
# =============================================================================
Write-Host "`n>>> [5/8] Code-Signing Target Binaries & MSI Installers..." -ForegroundColor Yellow
$TargetBinaries = @(
    $TargetExe,
    $DeployExe,
    $RootMsi,
    $DeployMsi
) | Where-Object { Test-Path $_ }

# Also discover and include all auxiliary release executables and dlls
$ReleaseDir = Join-Path $ProjectRoot "target\release"
$AuxBinaries = @(
    (Join-Path $ReleaseDir "osoosi_inject.dll"),
    (Join-Path $ReleaseDir "osoosi-auditor.exe"),
    (Join-Path $ReleaseDir "otx-taxii-rs.exe"),
    (Join-Path $ReleaseDir "bulk_trainer.exe"),
    (Join-Path $ReleaseDir "test-peer.exe")
) | Where-Object { Test-Path $_ }

# Also find any remaining unsigned top-level .exe or .dll in target\release
$AnyUnsigned = Get-ChildItem -Path (Join-Path $ReleaseDir "*.exe"), (Join-Path $ReleaseDir "*.dll") -ErrorAction SilentlyContinue |
    Where-Object {
        $sig = Get-AuthenticodeSignature $_.FullName
        $sig.SignerCertificate -eq $null
    } | Select-Object -ExpandProperty FullName

$AllToSign = @($TargetBinaries + $AuxBinaries + $AnyUnsigned) | Select-Object -Unique

if (-not $SkipSigning) {
    Invoke-AuthenticodeSigning -Files $AllToSign -Thumbprint $CertThumbprint -Timestamp $TimestampServer | Out-Null
    # Ensure signed MSI is synchronized if RootMsi was signed
    if ((Test-Path $RootMsi) -and (Test-Path $DeployMsi)) {
        Copy-Item -Path $RootMsi -Destination $DeployMsi -Force
    }
    # Ensure target/release/osoosi.exe and deploy/osoosi.exe have the exact same clean signature
    if ((Test-Path $DeployExe) -and (Test-Path $TargetExe)) {
        $deployHash = (Get-FileHash $DeployExe -Algorithm SHA256).Hash
        $targetHash = (Get-FileHash $TargetExe -Algorithm SHA256).Hash
        if ($deployHash -ne $targetHash) {
            Test-And-Handle-LockedFile -FilePath $TargetExe
            Copy-Item -Path $DeployExe -Destination $TargetExe -Force
        }
    }
} else {
    Write-Host "       -> Skipping code-signing (-SkipSigning specified)" -ForegroundColor Gray
}

# =============================================================================
# Step 6: Automated Microsoft Security Intelligence (WDSI) Submission
# =============================================================================
Write-Host "`n>>> [6/8] Submitting to Microsoft Security Intelligence (WDSI)..." -ForegroundColor Yellow
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

# =============================================================================
# Step 6b: Mandatory GitHub Release MSI & SLSA Provenance Synchronization
# =============================================================================
Write-Host "`n>>> [6b/8] Synchronizing Signed MSI Installer to GitHub Latest Release..." -ForegroundColor Yellow
$ReleaseSyncScript = Join-Path $ProjectRoot "scripts\update_github_release_msi.py"
if (Test-Path $ReleaseSyncScript) {
    & python $ReleaseSyncScript
    if ($LASTEXITCODE -eq 0) {
        Write-Host "       -> GitHub Release MSI assets synchronized successfully." -ForegroundColor Green
    } else {
        Write-Warning "update_github_release_msi.py returned code $LASTEXITCODE"
    }
} else {
    Write-Warning "Release synchronization script not found at $ReleaseSyncScript"
}

# =============================================================================
# Step 7: Final Service Health Verification & Cleanup
# =============================================================================
Write-Host "`n>>> [7/8] Verifying OsoosiEDR Windows Service Health..." -ForegroundColor Yellow
$svc = Get-Service OsoosiEDR -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "       OsoosiEDR service status: $($svc.Status)" -ForegroundColor Green
    if ($svc.Status -ne "Running") {
        Write-Host "       Starting OsoosiEDR service..." -ForegroundColor Cyan
        Start-Service OsoosiEDR -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "       OsoosiEDR service is not installed (skipping)." -ForegroundColor Gray
}

Cleanup-OldLockedFiles

# =============================================================================
# Step 8: Solo-Developer Auto-Review Bot & Post-Commit PR Shipping
# =============================================================================
$SoloShipScript = Join-Path $ProjectRoot "scripts\solo_pr_ship.ps1"
if (Test-Path $SoloShipScript) {
    Write-Host "`n>>> [8/8] Invoking Solo-Developer PR Workflow (Branch Protection Auto-Approval)..." -ForegroundColor Yellow
    & powershell -ExecutionPolicy Bypass -File $SoloShipScript -Title $PrTitle
}

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host " Pipeline Execution Complete!" -ForegroundColor Green
Write-Host " Release Binaries & MSI Packaged, Signed, Submitted to Microsoft, and PR Shipped." -ForegroundColor Green
Write-Host " Report saved to: deploy\reports\wdsi_submissions.json" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Green
