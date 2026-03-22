# Grant Sysmon Event Log read access to the current user.
# Run this script as Administrator once. After that, OpenỌ̀ṣọ́ọ̀sì can read Sysmon logs without admin.
#
# Usage: Right-click PowerShell -> Run as Administrator, then:
#   cd path\to\openodidere
#   .\scripts\grant-sysmon-read.ps1

$ErrorActionPreference = "Stop"

$User = "$env:USERDOMAIN\$env:USERNAME"
Write-Host "Granting Sysmon read access to: $User" -ForegroundColor Cyan

# Add to Event Log Readers (built-in group; allows reading Windows Event Logs including Sysmon)
net localgroup "Event Log Readers" $User /add
if ($LASTEXITCODE -eq 0) {
    Write-Host "Added $User to 'Event Log Readers' group." -ForegroundColor Green
} else {
    Write-Host "If already a member, that's OK. Otherwise run: net localgroup `"Event Log Readers`" $User /add" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Restart OpenỌ̀ṣọ́ọ̀sì for the change to take effect." -ForegroundColor Yellow
