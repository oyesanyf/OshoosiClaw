@echo off
setlocal
echo ========================================================
echo  OpenOshoosi Autonomous LangGraph Defense Swarm Runner
echo ========================================================

set PYTHON_BIN=python
where python >nul 2>nul
if not %ERRORLEVEL% equ 0 (
    echo [!] Python is not in PATH. Please install Python 3.10+
    exit /b 1
)

set SCRIPT_DIR=%~dp0
set PYTHONPATH=%SCRIPT_DIR%src;%PYTHONPATH%

echo [*] Launching Defense Swarm FastAPI service on 127.0.0.1:4002...
%PYTHON_BIN% -m defense_swarm.cli start --host 127.0.0.1 --port 4002 %*
