param(
    [string]$Thumbprint = "9A6D3B509500813058EC63183476464FAC8F015B"
)

$Cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
if (-not $Cert) { $Cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue }

$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    $stCmd = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($stCmd) { $signtool = $stCmd.Source }
}

Write-Host "[WDAC] Fast Signing unsigned test binaries and dependencies..."

$targets = @()
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "osoosi_wire-*.exe" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "osoosi_core-*.exe" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "osoosi_policy-*.exe" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "osoosi_agent_anomaly-*.exe" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "osoosi_dashboard-*.exe" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "*.dll" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\build" -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue

$signedCount = 0
foreach ($f in $targets) {
    try {
        $sig = Get-AuthenticodeSignature $f.FullName -ErrorAction SilentlyContinue
        if ((-not $sig) -or ($sig.SignerCertificate -eq $null) -or ($sig.Status -eq "UnknownError")) {
            $signed = $false
            if (Test-Path $signtool) {
                & $signtool sign /sha1 $Thumbprint /fd SHA256 /q $f.FullName 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $signedCount++
                    $signed = $true
                }
            }
            if ((-not $signed) -and $Cert) {
                $res = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $Cert -HashAlgorithm SHA256 -ErrorAction SilentlyContinue
                if ($res -and $res.SignerCertificate) {
                    $signedCount++
                }
            }
        }
    } catch {}
}

Write-Host "[WDAC] Fast signed $signedCount target test binaries and DLLs."
