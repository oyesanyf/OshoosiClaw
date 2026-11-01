# Run nightly RAPTOR SAST + Post-Quantum Crypto + SCA Security Audit for OshoosiClaw
param(
    [switch]$InstallScheduledTask = $false,
    [string]$TaskName = "OshoosiClaw-Nightly-Raptor-Security-Audit"
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ScriptSelf = $MyInvocation.MyCommand.Path

if ($InstallScheduledTask) {
    $Action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptSelf`"" `
        -WorkingDirectory $RepoRoot
    $Trigger = New-ScheduledTaskTrigger -Daily -At "02:30AM"
    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2)

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Settings $Settings `
        -Description "Nightly RAPTOR SAST, Post-Quantum Crypto, and SCA Security Audit for OshoosiClaw" `
        -Force | Out-Null

    Write-Host "[+] Registered Windows Scheduled Task '$TaskName' (Daily at 02:30 AM)." -ForegroundColor Green
    exit 0
}

Set-Location $RepoRoot
$LogDir = Join-Path $RepoRoot "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogDir "nightly_raptor_audit_${Timestamp}.log"

"[$(Get-Date -Format 'o')] Starting Nightly RAPTOR Security Audit..." | Out-File -FilePath $LogFile -Encoding utf8

if (Test-Path "D:\docker\raptor\Invoke-RaptorScan.ps1") {
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File "D:\docker\raptor\Invoke-RaptorScan.ps1" -TargetPath $RepoRoot -Mode all *>> $LogFile
    } catch {
        "[$(Get-Date -Format 'o')] Local Docker RAPTOR warning: $($_.Exception.Message)" | Out-File -FilePath $LogFile -Append -Encoding utf8
    }
}

$OsoosiExe = Join-Path $RepoRoot "target\release\osoosi.exe"
if (Test-Path $OsoosiExe) {
    & $OsoosiExe run pentest --list-findings *>> $LogFile
}

# Trigger GitHub Actions nightly workflow dispatch if gh CLI is authenticated
try {
    & gh workflow run raptor-security.yml --repo oyesanyf/OshoosiClaw *>> $LogFile
} catch {
    "[$(Get-Date -Format 'o')] GitHub workflow dispatch note: $($_.Exception.Message)" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

"[$(Get-Date -Format 'o')] Completed Nightly RAPTOR Security Audit." | Out-File -FilePath $LogFile -Append -Encoding utf8
