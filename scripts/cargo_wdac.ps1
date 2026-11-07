<#
.SYNOPSIS
    cargo_wdac.ps1 - Runs Cargo commands with automated Authenticode signing of build-script executables
    and proc-macro DLLs to satisfy Windows Defender Application Control (WDAC).
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B"

# 1. Discover signtool
$CandidateSignTools = @(
    (Get-Command "signtool.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"
)
$SignTool = $null
foreach ($cand in $CandidateSignTools) {
    if ($cand -and (Test-Path $cand)) {
        $SignTool = $cand
        break
    }
}

function Sign-TargetBinaries {
    if (-not $SignTool) { return }
    $dirs = @(
        (Join-Path $ProjectRoot "target\debug\build\*\*.exe"),
        (Join-Path $ProjectRoot "target\release\build\*\*.exe"),
        (Join-Path $ProjectRoot "target\debug\deps\*.dll"),
        (Join-Path $ProjectRoot "target\release\deps\*.dll")
    )
    $files = @()
    foreach ($pat in $dirs) {
        $found = Get-ChildItem -Path $pat -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        if ($found) {
            $files += $found
        }
    }
    if ($files.Count -eq 0) { return }
    for ($i = 0; $i -lt $files.Count; $i += 40) {
        $end = [Math]::Min($i + 39, $files.Count - 1)
        $batch = $files[$i..$end]
        & $SignTool sign /sha1 $CertThumbprint /fd SHA256 /q $batch 2>$null | Out-Null
    }
}

# Sign existing build exes and proc-macro dlls before starting
Sign-TargetBinaries

# Run cargo in a retry loop if WDAC blocks newly compiled build scripts or proc macros
$success = $false
for ($attempt = 1; $attempt -le 30; $attempt++) {
    & cargo $CargoArgs
    if ($LASTEXITCODE -eq 0) {
        $success = $true
        break
    }
    Sign-TargetBinaries
    Start-Sleep -Milliseconds 400
}

if (-not $success) {
    exit 1
}
