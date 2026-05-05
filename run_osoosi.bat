@echo off
setlocal enabledelayedexpansion

echo ====================================================
echo  OpenOdidere (Osoosi) Agentic EDR Runner
echo ====================================================

:: 1. Check for Admin Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: This agent must be run as ADMINISTRATOR.
    echo Please right-click this batch file and select 'Run as administrator'.
    pause
    exit /b 1
)

:: 2. Set Environment for better performance/logs
set RUST_LOG=osoosi=info,consensus=info
set OSOOSI_LOG_DIR=logs
if not exist logs mkdir logs

:: 3. Verify core assets
if not exist osoosi.exe (
    echo [!] ERROR: osoosi.exe not found in this directory.
    pause
    exit /b 1
)

if not exist models (
    echo [!] WARNING: 'models' directory not found. 
    echo AI models will be downloaded on first start (approx 6GB).
)

if not exist yara (
    echo [!] WARNING: 'yara' directory not found.
    echo Static signature detection will be limited.
)

:: 4. Launch the agent
echo [*] Starting Osoosi Agent...
osoosi.exe

if %errorLevel% neq 0 (
    echo [!] Agent exited with error code %errorLevel%
    pause
)
