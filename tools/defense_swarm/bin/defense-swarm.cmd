@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%.."
set "PYTHONPATH=%ROOT_DIR%\src;%PYTHONPATH%"

python -m defense_swarm.cli %*
endlocal
