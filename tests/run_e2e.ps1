# OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (OshoosiClaw) - E2E Test Suite PowerShell Wrapper
param(
    [switch]$All = $true,
    [switch]$WebUIOnly = $false,
    [switch]$FeaturesOnly = $false
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Get-Location }
Set-Location $ProjectRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " OpenỌ̀ṣọ́ọ̀sì Autonomous EDR - E2E Comprehensive Test Execution" -ForegroundColor Cyan
Write-Host " Root: $ProjectRoot" -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan

if ($WebUIOnly) {
    Write-Host "[RUN] Executing Node.js WebUI Test Suite..." -ForegroundColor Yellow
    node --test dashboard/tests/*.test.mjs
    exit $LASTEXITCODE
}

if ($FeaturesOnly) {
    Write-Host "[RUN] Executing Tier 1 Feature Coverage (150 tests)..." -ForegroundColor Yellow
    python tests/e2e/tier1_features_test.py
    exit $LASTEXITCODE
}

Write-Host "[RUN] Executing Full Multi-Tier E2E Test Suite (Tiers 1-4 + WebUI)..." -ForegroundColor Green
python tests/e2e/run_e2e_suite.py
exit $LASTEXITCODE
