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
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "*.exe" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\deps" -Filter "*.dll" -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\build" -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
$targets += Get-ChildItem -Path "target\debug\build" -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue

$signedCount = 0
foreach ($f in $targets) {
    try {
        if (-not (Test-Path $f.FullName)) { continue }
        # Break any Cargo NTFS hardlink (e.g. build-script-build.exe <-> build_script_build-<hash>.exe)
        # before running signtool so Windows 11 Smart App Control preserves the original link.exe inode EA.
        $hlOut = & fsutil hardlink list $f.FullName 2>$null
        if ($hlOut -and ($hlOut.Count -gt 1)) {
            $targetFull = [System.IO.Path]::GetFullPath($f.FullName)
            $driveRoot = [System.IO.Path]::GetPathRoot($targetFull).TrimEnd('\')
            # Prefer preserving build-script-build.exe over build_script_build-<hash>.exe
            if ($f.Name -like "build_script_build-*.exe") {
                continue
            }
            foreach ($hlRel in $hlOut) {
                $hlCandidate = "$driveRoot$hlRel"
                if ([System.IO.Path]::GetFullPath($hlCandidate) -ne $targetFull) {
                    Remove-Item -Path $hlCandidate -Force -ErrorAction SilentlyContinue
                }
            }
        }
        $sig = Get-AuthenticodeSignature $f.FullName -ErrorAction SilentlyContinue
        if ((-not $sig) -or ($sig.SignerCertificate -eq $null)) {
            $signed = $false
            $wt = $f.LastWriteTimeUtc
            if (Test-Path $signtool) {
                & $signtool sign /sha1 $Thumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /q $f.FullName 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    & $signtool sign /sha1 $Thumbprint /fd SHA256 /q $f.FullName 2>$null | Out-Null
                }
                if ($LASTEXITCODE -eq 0) {
                    $signedCount++
                    $signed = $true
                    try { (Get-Item $f.FullName).LastWriteTimeUtc = $wt } catch {}
                }
            }
            if ((-not $signed) -and $Cert) {
                $res = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $Cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" -ErrorAction SilentlyContinue
                if ((-not $res) -or (-not $res.SignerCertificate)) {
                    $res = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $Cert -HashAlgorithm SHA256 -ErrorAction SilentlyContinue
                }
                if ($res -and $res.SignerCertificate) {
                    $signedCount++
                    try { (Get-Item $f.FullName).LastWriteTimeUtc = $wt } catch {}
                }
            }
        }
    } catch {}
}

Write-Host "[WDAC] Fast signed $signedCount target test binaries and DLLs."
