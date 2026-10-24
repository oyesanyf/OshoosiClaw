<#
.SYNOPSIS
  Adds/removes the OshoosiClaw Browser DLP Sensor in the Chromium enterprise policy
  ExtensionInstallForcelist for Google Chrome and Microsoft Edge (HKLM\SOFTWARE\Policies).

.DESCRIPTION
  Chromium reads list policies as consecutive values "1", "2", "3", ... and stops at the first
  gap, so this script never overwrites an existing enterprise entry:
    - Install   : reuses the index already holding our extension ID, otherwise appends at the
                  first free index.
    - Uninstall : removes our value and renumbers the following values down so no gap remains.
  Only the policy keys below are touched. PATH and environment-variable hives are never read
  or written.

  NOTE: Chrome/Edge honour off-store force-install entries only on managed devices (domain
  joined, Azure AD/Entra joined, or MDM enrolled). On unmanaged home PCs use the documented
  "Load unpacked" flow (README) or publish to the Chrome Web Store / Edge Add-ons.

.PARAMETER Action
  Install | Uninstall | Status

.PARAMETER ExtensionId
  32-char Chromium extension ID (a-p). Defaults to browser-extension\extension_id.txt next to
  this script's install folder, else the built-in unpacked sensor ID.

.PARAMETER UpdateUrl
  Update manifest URL. Defaults to the local daemon: http://127.0.0.1:3030/browser-sensor/update.xml
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status')]
    [string]$Action = 'Status',
    [string]$ExtensionId = '',
    [string]$UpdateUrl = 'http://127.0.0.1:3030/browser-sensor/update.xml'
)

$ErrorActionPreference = 'Stop'
$DefaultId = 'mgkckbmpncmidjdkfeamongahgbheocl'
$PolicyKeys = @(
    'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
)

$explicitId = [bool]$ExtensionId
$packagedIdFound = $false
if (-not $ExtensionId) {
    $candidates = @(
        (Join-Path $PSScriptRoot 'browser-extension\extension_id.txt'),
        (Join-Path $PSScriptRoot '..\dist\browser-extension\extension_id.txt'),
        (Join-Path $PSScriptRoot 'extension_id.txt')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) {
            $ExtensionId = (Get-Content -LiteralPath $c -Raw).Trim()
            $packagedIdFound = $true
            break
        }
    }
    if (-not $ExtensionId) { $ExtensionId = $DefaultId }
}
if ($ExtensionId -notmatch '^[a-p]{32}$') {
    throw "Invalid Chromium extension ID '$ExtensionId'"
}
$Entry = "$ExtensionId;$UpdateUrl"
if ($Action -eq 'Install' -and -not $explicitId -and -not $packagedIdFound) {
    Write-Output 'No packed sensor CRX (extension_id.txt) found; skipping force-install. Use the documented Load unpacked flow.'
    exit 0
}

function Get-ListEntries([string]$Key) {
    $result = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Key)) { return $result }
    $props = Get-ItemProperty -LiteralPath $Key
    $i = 1
    while ($true) {
        $name = [string]$i
        $value = $props.PSObject.Properties[$name]
        if ($null -eq $value) { break }
        $result[$name] = [string]$value.Value
        $i++
    }
    return $result
}

foreach ($key in $PolicyKeys) {
    $entries = Get-ListEntries $key
    $ours = @($entries.Keys | Where-Object { $entries[$_].Split(';')[0].Trim() -eq $ExtensionId })
    switch ($Action) {
        'Status' {
            Write-Output ("{0}: {1}" -f $key, $(if ($ours.Count) { "present at index $($ours -join ',')" } else { 'not present' }))
        }
        'Install' {
            if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
            if ($ours.Count -gt 0) {
                Set-ItemProperty -LiteralPath $key -Name $ours[0] -Value $Entry -Type String
                Write-Output "${key}: updated index $($ours[0])"
            } else {
                $next = [string]($entries.Count + 1)
                New-ItemProperty -LiteralPath $key -Name $next -Value $Entry -PropertyType String -Force | Out-Null
                Write-Output "${key}: added at index $next"
            }
        }
        'Uninstall' {
            if ($ours.Count -eq 0) { Write-Output "${key}: nothing to remove"; continue }
            $kept = @($entries.Keys | Where-Object { $ours -notcontains $_ } | ForEach-Object { $entries[$_] })
            foreach ($name in @($entries.Keys)) { Remove-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue }
            for ($i = 0; $i -lt $kept.Count; $i++) {
                New-ItemProperty -LiteralPath $key -Name ([string]($i + 1)) -Value $kept[$i] -PropertyType String -Force | Out-Null
            }
            Write-Output "${key}: removed sensor entry; $($kept.Count) other entr(y/ies) renumbered without gaps"
        }
    }
}
