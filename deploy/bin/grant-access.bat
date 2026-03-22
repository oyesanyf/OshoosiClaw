@echo off
echo ============================================================
echo OpenOsoosi: Elevated Access Tool
echo ============================================================
echo.
echo This tool will grant OpenOsoosi access to security logs
echo and enable the Repair Engine (Patching).
echo.
echo IMPORTANT: This script will attempt to run as Administrator.
echo.

:: Check for privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running as Administrator.
) else (
    echo [!] Requesting Administrative privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
osoosi.exe grant-access
echo.
echo [DONE] You can now start the agent: osoosi.exe start
pause
