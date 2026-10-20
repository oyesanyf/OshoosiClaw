# =============================================================================
# OpenỌ̀ṣọ́ọ̀sì Autonomous EDR - Windows Ring-0 Drivers Build & Sign Script
# Compiles and Authenticode-signs:
#   1. driver\windows\osoosi_driver.sys (Ring-0 Minifilter + ObRegisterCallbacks + PsSetCreateProcessNotifyRoutineEx + BYOVD Image Load Guard)
#   2. driver\windows\osoosi_elam.sys   (Boot-Start Early Launch Anti-Malware Driver + MicrosoftElamCertificateInfo resource table)
# =============================================================================
param(
    [string]$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B",
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
$DriverDir = Join-Path $ProjectRoot "driver\windows"
$SrcDir    = Join-Path $DriverDir "src"
$IncDir    = Join-Path $DriverDir "include"
$DefFile   = Join-Path $DriverDir "ntoskrnl.def"

# Discover MSVC cl.exe, link.exe, lib.exe
$msvcRoot = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC"
if (-not (Test-Path $msvcRoot)) {
    $msvcRoot = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
}
$msvcBin = Get-ChildItem $msvcRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
if (-not $msvcBin) {
    throw "Could not locate MSVC build tools under $msvcRoot"
}
$binX64 = Join-Path $msvcBin.FullName "bin\Hostx64\x64"
$clExe   = Join-Path $binX64 "cl.exe"
$linkExe = Join-Path $binX64 "link.exe"
$libExe  = Join-Path $binX64 "lib.exe"

# Discover Windows Kits rc.exe and signtool.exe
$sdkCandidates = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
)
$sdkBin = $sdkCandidates | Where-Object { Test-Path (Join-Path $_ "rc.exe") } | Select-Object -First 1
if (-not $sdkBin) {
    throw "Could not locate Windows 10/11 SDK bin\x64 directory"
}
$rcExe       = Join-Path $sdkBin "rc.exe"
$signtoolExe = Join-Path $sdkBin "signtool.exe"

$LibFile = Join-Path $DriverDir "ntoskrnl.lib"
$ExpFile = Join-Path $DriverDir "ntoskrnl.exp"

Write-Host ">>> [DRV 1/4] Generating ntoskrnl.lib import library..." -ForegroundColor Cyan
& $libExe /nologo "/def:$DefFile" "/out:$LibFile" /machine:x64 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "lib.exe failed to generate ntoskrnl.lib" }

Write-Host ">>> [DRV 2/4] Compiling osoosi_driver.sys (Ring-0 Minifilter + ObRegisterCallbacks + BYOVD Guard)..." -ForegroundColor Cyan
$DriverObj = Join-Path $DriverDir "osoosi_driver.obj"
$DriverSys = Join-Path $DriverDir "osoosi_driver.sys"
$DriverC   = Join-Path $SrcDir "osoosi_driver.c"

& $clExe /nologo /c /O2 /W4 /WX /GS- /Zl /kernel "/I$IncDir" "/Fo$DriverObj" $DriverC
if ($LASTEXITCODE -ne 0) { throw "cl.exe failed compiling osoosi_driver.c" }

& $linkExe /nologo /driver /subsystem:native /entry:DriverEntry /nodefaultlib /integritycheck "/out:$DriverSys" $DriverObj $LibFile
if ($LASTEXITCODE -ne 0) { throw "link.exe failed linking osoosi_driver.sys" }

Write-Host ">>> [DRV 3/4] Compiling osoosi_elam.sys (Early Launch Anti-Malware Driver + ELAM Resource)..." -ForegroundColor Cyan
$ElamRes = Join-Path $DriverDir "osoosi_elam.res"
$ElamObj = Join-Path $DriverDir "osoosi_elam.obj"
$ElamSys = Join-Path $DriverDir "osoosi_elam.sys"
$ElamRc  = Join-Path $SrcDir "osoosi_elam.rc"
$ElamC   = Join-Path $SrcDir "osoosi_elam.c"

& $rcExe /nologo "/fo$ElamRes" $ElamRc
if ($LASTEXITCODE -ne 0) { throw "rc.exe failed compiling osoosi_elam.rc" }

& $clExe /nologo /c /O2 /W4 /WX /GS- /Zl /kernel "/I$IncDir" "/Fo$ElamObj" $ElamC
if ($LASTEXITCODE -ne 0) { throw "cl.exe failed compiling osoosi_elam.c" }

& $linkExe /nologo /driver /subsystem:native /entry:DriverEntry /nodefaultlib /integritycheck "/out:$ElamSys" $ElamObj $ElamRes $LibFile
if ($LASTEXITCODE -ne 0) { throw "link.exe failed linking osoosi_elam.sys" }

# Clean up intermediate .obj/.exp/.lib/.res files so git working tree stays clean
Remove-Item -Force $DriverObj, $ElamObj, $ElamRes, $LibFile, $ExpFile -ErrorAction SilentlyContinue

Write-Host ">>> [DRV 4/4] Authenticode Signing osoosi_driver.sys and osoosi_elam.sys (Page Hashing + SHA-256 + RFC 3161)..." -ForegroundColor Cyan
foreach ($sys in @($DriverSys, $ElamSys)) {
    & $signtoolExe sign /sha1 $CertThumbprint /fd SHA256 /ph /tr $TimestampServer /td SHA256 $sys | Out-Null
    if ($LASTEXITCODE -ne 0) {
        & $signtoolExe sign /sha1 $CertThumbprint /fd SHA256 /ph $sys | Out-Null
    }
    $sig = Get-AuthenticodeSignature $sys
    if ($null -eq $sig.SignerCertificate) {
        throw "CRITICAL: Kernel driver $sys is not Authenticode signed!"
    }
    Write-Host "       -> Signed & Verified: $sys ($($sig.SignerCertificate.Subject))" -ForegroundColor Green
}
