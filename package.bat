@echo off
setlocal enabledelayedexpansion

echo ====================================================
echo  OshoosiClaw Production Packaging Script
echo ====================================================

:: 1. Verify binaries exist
echo [1/6] Checking for existing release binaries...
set TARGET_BIN=target\release\osoosi.exe
if not exist !TARGET_BIN! set TARGET_BIN=target\x86_64-pc-windows-msvc\release\osoosi.exe
if not exist !TARGET_BIN! (
    echo [!] 'target\release\osoosi.exe' not found.
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
mkdir %DEPLOY_DIR%\config

:: 3. Copy binaries and core assets
echo [3/6] Collecting binaries and core assets...
set TARGET_DIR=target\release
if not exist %TARGET_DIR%\osoosi.exe set TARGET_DIR=target\x86_64-pc-windows-msvc\release
copy %TARGET_DIR%\osoosi.exe %DEPLOY_DIR%\
if exist %TARGET_DIR%\osoosi_inject.dll copy %TARGET_DIR%\osoosi_inject.dll %DEPLOY_DIR%\
if exist %TARGET_DIR%\test-peer.exe copy %TARGET_DIR%\test-peer.exe %DEPLOY_DIR%\
if exist %TARGET_DIR%\onnxruntime.dll copy %TARGET_DIR%\onnxruntime.dll %DEPLOY_DIR%\
if exist onnxruntime.dll copy onnxruntime.dll %DEPLOY_DIR%\
if exist run_osoosi.bat copy run_osoosi.bat %DEPLOY_DIR%\
copy osoosi.toml %DEPLOY_DIR%\
if exist osoosi.toml.sign copy osoosi.toml.sign %DEPLOY_DIR%\
if exist config xcopy /s /e /y config\* %DEPLOY_DIR%\config\
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
echo [5/6] Collecting dashboard UI assets...
if exist dashboard\dist (
    xcopy /s /e /y dashboard\dist\* %DEPLOY_DIR%\dashboard\dist\
) else if exist crates\osoosi-dashboard\dist (
    xcopy /s /e /y crates\osoosi-dashboard\dist\* %DEPLOY_DIR%\dashboard\dist\
)

:: 6. Build WiX MSI Installer
echo [6/6] Building WiX MSI Installer...
if exist wix\OshoosiClaw.wxs (
    set WIX_EXE=wix
    where wix >nul 2>nul
    if not !ERRORLEVEL! equ 0 (
        if exist "C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin\wix.exe" (
            set WIX_EXE="C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin\wix.exe"
        )
    )
    if not exist target\release\onnxruntime.dll if exist onnxruntime.dll copy onnxruntime.dll target\release\onnxruntime.dll
    !WIX_EXE! build wix\OshoosiClaw.wxs -arch x64 -out OshoosiClaw.msi
    if exist OshoosiClaw.msi (
        copy OshoosiClaw.msi %DEPLOY_DIR%\OshoosiClaw.msi
        echo   [+] Successfully built OshoosiClaw.msi
    )
)

:: 7. Create ZIP Archive (Using PowerShell for better compression/compatibility)
echo Creating portable zip archive...
set ZIP_NAME=osoosi_portable.zip
if exist %ZIP_NAME% del %ZIP_NAME%
powershell -Command "Compress-Archive -Path '%DEPLOY_DIR%\*' -DestinationPath '%ZIP_NAME%' -Force"

echo ====================================================
echo  Package Complete: %ZIP_NAME% and OshoosiClaw.msi
echo  The packages are ready for deployment.
echo ====================================================
pause
