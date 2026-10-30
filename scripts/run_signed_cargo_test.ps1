param(
    [string]$Command = "cargo test -p osoosi-core --lib threshold_secret"
)

$Thumbprint = "9A6D3B509500813058EC63183476464FAC8F015B"

for ($attempt = 1; $attempt -le 25; $attempt++) {
    Write-Host "[WDAC Runner] Attempt $attempt/25: Signing test binaries before run..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File scripts/sign_debug_test_binaries.ps1

    Write-Host "[WDAC Runner] Executing: $Command" -ForegroundColor Yellow
    Invoke-Expression $Command
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[WDAC Runner] Succeeded on attempt $attempt!" -ForegroundColor Green
        exit 0
    }

    Write-Host "[WDAC Runner] Failed on attempt $attempt (exit code $LASTEXITCODE). Fast signing newly generated build scripts..." -ForegroundColor Yellow
    & powershell -ExecutionPolicy Bypass -File scripts/sign_debug_test_binaries.ps1
    Start-Sleep -Seconds 1
}

Write-Error "[WDAC Runner] Command did not succeed within 25 attempts."
exit 1
