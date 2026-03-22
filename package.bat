@echo off
setlocal enabledelayedexpansion

echo ====================================================
echo  OpenOdidere (Osoosi) Build ^& Package Script
echo ====================================================

:: 1. Verify binaries exist
echo [1/5] Checking for existing release binaries...
if not exist target\release\osoosi.exe (
    echo [!] 'target\release\osoosi.exe' not found.
    echo Please run 'cargo build --release' first or use a build script.
    exit /b 1
)

:: 2. Prepare deployment folder
echo [2/5] Preparing deployment directory...
set DEPLOY_DIR=osoosi_deploy
if exist %DEPLOY_DIR% rm-rf %DEPLOY_DIR% 2>nul
if exist %DEPLOY_DIR% rd /s /q %DEPLOY_DIR%
mkdir %DEPLOY_DIR%
mkdir %DEPLOY_DIR%\config
mkdir %DEPLOY_DIR%\yara
mkdir %DEPLOY_DIR%\models
mkdir %DEPLOY_DIR%\logs

:: 3. Copy binaries and core assets
echo [3/5] Collecting files...
copy target\release\osoosi.exe %DEPLOY_DIR%\
copy target\release\test-peer.exe %DEPLOY_DIR%\
if exist osoosi.toml (
    copy osoosi.toml %DEPLOY_DIR%\
) else if exist osoosi.toml.example (
    copy osoosi.toml.example %DEPLOY_DIR%\osoosi.toml
)

:: Copy Sysmon for EDR
if exist Sysmon64.exe copy Sysmon64.exe %DEPLOY_DIR%\
if exist sysmonconfig-export.xml copy sysmonconfig-export.xml %DEPLOY_DIR%\

:: Copy Configs, scripts, and UI
if exist config xcopy /s /e /y config\* %DEPLOY_DIR%\config\
if exist scripts\firewall_setup.ps1 copy scripts\firewall_setup.ps1 %DEPLOY_DIR%\
if exist scripts\firewall_setup.sh copy scripts\firewall_setup.sh %DEPLOY_DIR%\

:: Copy UI Assets (must be in dashboard/dist for the agent to find them)
echo [3.5/5] Collecting dashboard UI assets...
if exist dashboard\dist (
    mkdir %DEPLOY_DIR%\dashboard\dist
    xcopy /s /e /y dashboard\dist\* %DEPLOY_DIR%\dashboard\dist\
) else (
    echo [!] Warning: 'dashboard\dist' not found. Dashboard UI will be missing.
)

:: 4. Find ONNX Runtime DLLs (LocalAppData cache)
echo [4/5] Checking for native dependencies (ONNX)...
set ORT_CACHE=%LOCALAPPDATA%\ort.pyke.io\dfbin\x86_64-pc-windows-msvc
if exist "%ORT_CACHE%" (
    for /r "%ORT_CACHE%" %%f in (onnxruntime*.dll) do (
        copy "%%f" %DEPLOY_DIR%\ >nul
        echo    -^> Added %%~nxf
    )
)

:: 5. Create ZIP Archive
echo [5/5] Creating zip archive...
set ZIP_NAME=osoosi_portable.zip
if exist %ZIP_NAME% del %ZIP_NAME%
tar -a -c -f %ZIP_NAME% %DEPLOY_DIR%

echo ====================================================
echo  Package Complete: %ZIP_NAME%
echo  Copy this zip to another computer to deploy.
echo ====================================================
