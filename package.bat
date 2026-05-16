@echo off
setlocal enabledelayedexpansion

echo ====================================================
echo  OshoosiClaw Production Packaging Script
echo ====================================================

:: 1. Verify binaries exist
echo [1/5] Checking for existing release binaries...
if not exist target\x86_64-pc-windows-msvc\release\osoosi.exe (
    echo [!] 'target\x86_64-pc-windows-msvc\release\osoosi.exe' not found.
    echo Please run 'cargo build --release' first.
    exit /b 1
)

:: 2. Prepare deployment folder
echo [2/5] Preparing deployment directory...
set DEPLOY_DIR=osoosi_deploy
if exist %DEPLOY_DIR% rd /s /q %DEPLOY_DIR%
mkdir %DEPLOY_DIR%
mkdir %DEPLOY_DIR%\yara
mkdir %DEPLOY_DIR%\models
mkdir %DEPLOY_DIR%\logs
mkdir %DEPLOY_DIR%\dashboard\dist

:: 3. Copy binaries and core assets
echo [3/5] Collecting binaries and core assets...
copy target\x86_64-pc-windows-msvc\release\osoosi.exe %DEPLOY_DIR%\
copy target\x86_64-pc-windows-msvc\release\osoosi_inject.dll %DEPLOY_DIR%\
copy target\x86_64-pc-windows-msvc\release\test-peer.exe %DEPLOY_DIR%\
copy run_osoosi.bat %DEPLOY_DIR%\
copy osoosi.toml %DEPLOY_DIR%\
if exist deceptive_techniques.py copy deceptive_techniques.py %DEPLOY_DIR%\

:: Copy YARA rules
if exist yara xcopy /s /e /y yara\* %DEPLOY_DIR%\yara\

:: 4. Copy AI Models (Selective - Skip heavy weights to keep package portable)
echo [4/5] Collecting AI model configurations (skipping heavy weights)...
:: Copy only JSON and small config files. Large .onnx_data / .safetensors will be auto-downloaded by the agent.
for /r models %%f in (*.json) do (
    set "rel_path=%%~pf"
    set "rel_path=!rel_path:*models\=!"
    if not exist "%DEPLOY_DIR%\models\!rel_path!" mkdir "%DEPLOY_DIR%\models\!rel_path!"
    copy "%%f" "%DEPLOY_DIR%\models\!rel_path!" >nul
)

echo "NOTE: Heavy AI model weights (.onnx_data, .safetensors) were excluded to keep this package portable." > %DEPLOY_DIR%\models\README_AI.txt
echo "The Oshoosi agent will autonomously download required weights on first start." >> %DEPLOY_DIR%\models\README_AI.txt

:: 5. Copy Dashboard UI
echo [5/5] Collecting dashboard UI assets...
if exist dashboard\dist (
    xcopy /s /e /y dashboard\dist\* %DEPLOY_DIR%\dashboard\dist\
) else if exist crates\osoosi-dashboard\dist (
    xcopy /s /e /y crates\osoosi-dashboard\dist\* %DEPLOY_DIR%\dashboard\dist\
)

:: 6. Create ZIP Archive (Using PowerShell for better compression/compatibility)
echo [6/5] Creating portable zip archive...
set ZIP_NAME=osoosi_portable.zip
if exist %ZIP_NAME% del %ZIP_NAME%
powershell -Command "Compress-Archive -Path '%DEPLOY_DIR%\*' -DestinationPath '%ZIP_NAME%' -Force"

echo ====================================================
echo  Package Complete: %ZIP_NAME%
echo  The package is now significantly smaller and ready for deployment.
echo ====================================================
pause
