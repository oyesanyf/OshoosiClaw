# Google CAGE Governance Substrate - E2E Test Suite PowerShell Wrapper
param(
    [switch]$Tier1Only = $false,
    [switch]$Tier2Only = $false,
    [switch]$Tier3Only = $false,
    [switch]$Tier4Only = $false
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Get-Location }
Set-Location $ProjectRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Google Cybernetic Agent Governance Engine (CAGE) Native Substrate" -ForegroundColor Cyan
Write-Host " Comprehensive E2E Test Execution" -ForegroundColor Cyan
Write-Host " Root: $ProjectRoot" -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan

if ($Tier1Only) {
    Write-Host "[RUN] Executing Tier 1 Feature Coverage (75 tests)..." -ForegroundColor Yellow
    python tests/e2e_cage_governance/run_suite.py --tier 1
    exit $LASTEXITCODE
}

if ($Tier2Only) {
    Write-Host "[RUN] Executing Tier 2 Boundary Cases (75 tests)..." -ForegroundColor Yellow
    python tests/e2e_cage_governance/run_suite.py --tier 2
    exit $LASTEXITCODE
}

if ($Tier3Only) {
    Write-Host "[RUN] Executing Tier 3 Cross-Feature Combinations (16 tests)..." -ForegroundColor Yellow
    python tests/e2e_cage_governance/run_suite.py --tier 3
    exit $LASTEXITCODE
}

if ($Tier4Only) {
    Write-Host "[RUN] Executing Tier 4 Real-World Application Scenarios (8 tests)..." -ForegroundColor Yellow
    python tests/e2e_cage_governance/run_suite.py --tier 4
    exit $LASTEXITCODE
}

Write-Host "[RUN] Executing Full Multi-Tier E2E Test Suite (Tiers 1-4, 174 tests)..." -ForegroundColor Green
python tests/e2e_cage_governance/run_suite.py
exit $LASTEXITCODE
