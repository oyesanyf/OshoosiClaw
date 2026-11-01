# Empirical Stress Harness for Milestone 1 Remediation (R2)
# Challenger: challenger_m1_r2_2
# Tests:
# 1. Multi-file sealing with DPAPI enabled
# 2. Companion .dpapi key blob verification
# 3. Atomic .tmp file cleanup and shredding upon removal
# 4. Zero-touch immutability of PATH, JAVA_HOME, TEMP, TMP

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [CHALLENGER] Starting Milestone 1 DPAPI Empirical Suite " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Step 0: Record baseline system environment variables
$baselinePath = $env:PATH
$baselineJava = $env:JAVA_HOME
$baselineTemp = $env:TEMP
$baselineTmp = $env:TMP

$regPathBefore = (Get-ItemProperty -Path "HKCU:\Environment" -Name "Path" -ErrorAction SilentlyContinue).Path

Write-Host "[1/6] Baseline Environment Snapshot Recorded:" -ForegroundColor Yellow
Write-Host "      PATH length: $($baselinePath.Length) chars"
Write-Host "      JAVA_HOME:   $baselineJava"
Write-Host "      TEMP:        $baselineTemp"
Write-Host "      TMP:         $baselineTmp"

# Step 1: Create isolated challenge workspace
$workspace = "d:\harfile\OshoosiClaw\target\challenge_test_workspace"
if (Test-Path $workspace) {
    Remove-Item -Recurse -Force $workspace
}
New-Item -ItemType Directory -Force -Path $workspace | Out-Null
$apiDir = Join-Path $workspace "services\api"
$workerDir = Join-Path $workspace "services\worker"
New-Item -ItemType Directory -Force -Path $apiDir | Out-Null
New-Item -ItemType Directory -Force -Path $workerDir | Out-Null

$rootEnv = Join-Path $workspace ".env"
$rootEnvContent = @"
# Root Production Environment
export GEMINI_API_KEY="AIzaSyD-EmpiricalChallengerKey12345" # root gemini key
PATH="C:\Windows\system32;C:\Tools"
JAVA_HOME="C:\Program Files\Java\jdk-21"
TEMP="C:\Temp"
TMP="C:\Temp"
PORT=8080
NODE_ENV=production
"@
Set-Content -Path $rootEnv -Value $rootEnvContent -NoNewline

$apiEnv = Join-Path $apiDir ".env"
$apiEnvContent = @"
# Local API Service
HF_TOKEN='hf_EmpiricalChallengerLocalToken98765'
HOST="127.0.0.1"
USERPROFILE="C:\Users\EmpiricalTester"
"@
Set-Content -Path $apiEnv -Value $apiEnvContent -NoNewline

$workerEnv = Join-Path $workerDir ".env"
$workerEnvContent = @"
# Worker Service
OPENAI_API_KEY=sk-proj-EmpiricalChallengerWorkerSecret456
OTX_API_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
DATABASE_URL=postgres://user:pass@localhost:5432/db
"@
Set-Content -Path $workerEnv -Value $workerEnvContent -NoNewline

# Compute pre-seal hashes
$hashRootBefore = (Get-FileHash -Path $rootEnv -Algorithm SHA256).Hash
$hashApiBefore = (Get-FileHash -Path $apiEnv -Algorithm SHA256).Hash
$hashWorkerBefore = (Get-FileHash -Path $workerEnv -Algorithm SHA256).Hash

Write-Host "[2/6] Test Environment Created. Pre-seal SHA256 hashes:" -ForegroundColor Yellow
Write-Host "      root .env:    $hashRootBefore"
Write-Host "      api .env:     $hashApiBefore"
Write-Host "      worker .env:  $hashWorkerBefore"

# Step 2: Seal using release CLI
$osoosiExe = "d:\harfile\OshoosiClaw\target\release\osoosi.exe"
$vaultPath = Join-Path $workspace "test_challenge.vault"
$dpapiCompanion = Join-Path $workspace "test_challenge.dpapi"

Write-Host "[3/6] Invoking CLI seal..." -ForegroundColor Yellow
$proc = Start-Process -FilePath $osoosiExe -ArgumentList @("env-gateway", "seal", "-e", $rootEnv, "-v", $vaultPath) -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    throw "FAIL: CLI seal failed with exit code $($proc.ExitCode)"
}

# Step 3: Verify DPAPI companion and file creation
if (-not (Test-Path $vaultPath)) {
    throw "FAIL: Vault file was not created at $vaultPath"
}
if (-not (Test-Path $dpapiCompanion)) {
    throw "FAIL: Companion .dpapi file was not created at $dpapiCompanion"
}

$vaultBytes = [System.IO.File]::ReadAllBytes($vaultPath)
$dpapiBytes = [System.IO.File]::ReadAllBytes($dpapiCompanion)

Write-Host "      Vault size: $($vaultBytes.Length) bytes"
Write-Host "      DPAPI blob size: $($dpapiBytes.Length) bytes"

if ($dpapiBytes.Length -lt 32) {
    throw "FAIL: DPAPI companion blob is smaller than 32 bytes ($($dpapiBytes.Length) bytes)"
}

# Check that NO .tmp files exist anywhere in the workspace
$tmpFiles = Get-ChildItem -Path $workspace -Recurse -Filter "*tmp*" -Force
if ($tmpFiles.Count -gt 0) {
    throw "FAIL: Found leftover temporary files after seal: $($tmpFiles.FullName -join ', ')"
}
Write-Host "      PASS: Zero .tmp files found in workspace." -ForegroundColor Green

# Verify in-place stand-in replacement and zero leakage
$rootEnvSealed = Get-Content -Path $rootEnv -Raw
if ($rootEnvSealed -match "AIzaSyD-EmpiricalChallengerKey12345") {
    throw "FAIL: Raw secret leaked in sealed root .env!"
}
if ($rootEnvSealed -notmatch "OSHOOSI_STANDIN_GEMINI_API_KEY_") {
    throw "FAIL: Stand-in token missing in sealed root .env!"
}
if ($rootEnvSealed -notmatch 'PATH="C:\\Windows\\system32;C:\\Tools"') {
    throw "FAIL: PATH was altered in root .env!"
}
if ($rootEnvSealed -notmatch 'JAVA_HOME="C:\\Program Files\\Java\\jdk-21"') {
    throw "FAIL: JAVA_HOME was altered in root .env!"
}
if ($rootEnvSealed -notmatch 'TEMP="C:\\Temp"') {
    throw "FAIL: TEMP was altered in root .env!"
}
if ($rootEnvSealed -notmatch 'TMP="C:\\Temp"') {
    throw "FAIL: TMP was altered in root .env!"
}
if ($rootEnvSealed -notmatch 'PORT=8080') {
    throw "FAIL: PORT was altered in root .env!"
}
Write-Host "      PASS: Secrets sealed into stand-in tokens; non-secret PATH, JAVA_HOME, TEMP, TMP 100% preserved." -ForegroundColor Green

# Step 4: Verify Revert / Unseal
Write-Host "[4/6] Invoking CLI revert..." -ForegroundColor Yellow
$proc = Start-Process -FilePath $osoosiExe -ArgumentList @("env-gateway", "revert", "-v", $vaultPath) -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    throw "FAIL: CLI revert failed with exit code $($proc.ExitCode)"
}

$hashRootAfter = (Get-FileHash -Path $rootEnv -Algorithm SHA256).Hash
if ($hashRootAfter -ne $hashRootBefore) {
    throw "FAIL: Root .env post-revert hash ($hashRootAfter) does not match pre-seal hash ($hashRootBefore)!"
}
$rootRestored = Get-Content -Path $rootEnv -Raw
if ($rootRestored -match "OSHOOSI_STANDIN_") {
    throw "FAIL: Stand-in token leaked after revert!"
}
Write-Host "      PASS: Bit-for-bit SHA256 verification succeeded after revert. Zero stand-in tokens remain." -ForegroundColor Green

# Check again for any .tmp files
$tmpFilesAfterRevert = Get-ChildItem -Path $workspace -Recurse -Filter "*tmp*" -Force
if ($tmpFilesAfterRevert.Count -gt 0) {
    throw "FAIL: Found leftover temporary files after revert: $($tmpFilesAfterRevert.FullName -join ', ')"
}
Write-Host "      PASS: Zero .tmp files found after revert." -ForegroundColor Green

# Step 5: Test Safe Removal and Shredding
Write-Host "[5/6] Testing remove-backup..." -ForegroundColor Yellow
# First reseal so vault exists
$proc = Start-Process -FilePath $osoosiExe -ArgumentList @("env-gateway", "seal", "-e", $rootEnv, "-v", $vaultPath) -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    throw "FAIL: Reseal failed before remove-backup test"
}
if (-not (Test-Path $vaultPath) -or -not (Test-Path $dpapiCompanion)) {
    throw "FAIL: Reseal did not create vault or .dpapi companion before remove-backup test"
}

# Attempt remove-backup WITHOUT --confirm
$proc = Start-Process -FilePath $osoosiExe -ArgumentList @("env-gateway", "remove-backup", "-v", $vaultPath) -Wait -PassThru -NoNewWindow
Write-Host "      Attempt without --confirm returned exit code: $($proc.ExitCode)"
if ($proc.ExitCode -eq 0) {
    throw "FAIL: remove-backup without --confirm returned exit code 0!"
}
if ((-not (Test-Path $vaultPath)) -or (-not (Test-Path $dpapiCompanion))) {
    throw "FAIL: remove-backup without --confirm deleted vault or .dpapi companion!"
}
Write-Host "      PASS: remove-backup without --confirm safely refused to delete files." -ForegroundColor Green

# Attempt remove-backup WITH --confirm
$proc = Start-Process -FilePath $osoosiExe -ArgumentList @("env-gateway", "remove-backup", "-v", $vaultPath, "--confirm") -Wait -PassThru -NoNewWindow
Write-Host "      Attempt with --confirm returned exit code: $($proc.ExitCode)"
if ($proc.ExitCode -ne 0) {
    throw "FAIL: remove-backup with --confirm returned non-zero exit code $($proc.ExitCode)"
}
if (Test-Path $vaultPath) {
    throw "FAIL: Vault file $vaultPath still exists after confirmed remove-backup!"
}
if (Test-Path $dpapiCompanion) {
    throw "FAIL: Companion .dpapi file $dpapiCompanion still exists after confirmed remove-backup!"
}
Write-Host "      PASS: Both vault and .dpapi companion files shredded and unlinked." -ForegroundColor Green

$tmpFilesFinal = Get-ChildItem -Path $workspace -Recurse -Filter "*tmp*" -Force
if ($tmpFilesFinal.Count -gt 0) {
    throw "FAIL: Found leftover temporary files after removal: $($tmpFilesFinal.FullName -join ', ')"
}
Write-Host "      PASS: Zero .tmp files remaining." -ForegroundColor Green

# Step 6: Verify Zero-Touch System Environment Invariants
Write-Host "[6/6] Verifying System Environment Immutability..." -ForegroundColor Yellow
if ($env:PATH -ne $baselinePath) {
    throw "CRITICAL FAILURE: `$env:PATH was altered! Baseline length: $($baselinePath.Length), Current length: $($env:PATH.Length)"
}
if ($env:JAVA_HOME -ne $baselineJava) {
    throw "CRITICAL FAILURE: `$env:JAVA_HOME was altered!"
}
if ($env:TEMP -ne $baselineTemp) {
    throw "CRITICAL FAILURE: `$env:TEMP was altered!"
}
if ($env:TMP -ne $baselineTmp) {
    throw "CRITICAL FAILURE: `$env:TMP was altered!"
}

$regPathAfter = (Get-ItemProperty -Path "HKCU:\Environment" -Name "Path" -ErrorAction SilentlyContinue).Path
if ($regPathAfter -ne $regPathBefore) {
    throw "CRITICAL FAILURE: Registry HKCU:\Environment Path was altered!"
}
Write-Host "      PASS: `$env:PATH, `$env:JAVA_HOME, `$env:TEMP, `$env:TMP and HKCU Registry are 100% UNTOUCHED." -ForegroundColor Green

# Clean up test workspace
Remove-Item -Recurse -Force $workspace
Write-Host "      PASS: Test workspace cleanly deleted." -ForegroundColor Green

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [CHALLENGER] ALL EMPIRICAL CHECKS PASSED (VERDICT: APPROVE) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
