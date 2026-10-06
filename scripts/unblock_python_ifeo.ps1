# scripts/unblock_python_ifeo.ps1 - Unblock Python binaries from IFEO debugger traps
# Run as Administrator

$ErrorActionPreference = "SilentlyContinue"

$hives = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)

$entries = @(
    "python.exe", "python3.exe", "pythonw.exe", "pythonw3.exe", "python3.14t_d.exe", "pythonw3.14t_d.exe",
    "python314_d.dll", "python3_d.dll", "python3t_d.dll", "py.exe", "pyw.exe", "py-manager.exe", "pymanager.exe",
    "pyw-manager.exe", "pywmanager.exe", "pyshellext.exe", "launcher-32.exe", "launcher-arm64.exe",
    "launcherw-32.exe", "launcherw-64.exe", "launcherw-arm64.exe", "venvlauncher_d.exe", "venvlaunchert_d.exe",
    "venvwlauncher_d.exe", "venvwlaunchert_d.exe", "pyexpat_d.pyd", "pyexpat_d.cp314t-win_amd64.pyd",
    "select_d.pyd", "select_d.cp314t-win_amd64.pyd", "sqlite3_d.dll", "unicodedata_d.pyd", "unicodedata_d.cp314t-win_amd64.pyd",
    "winsound_d.pyd", "winsound_d.cp314t-win_amd64.pyd", "_asyncio_d.pyd", "_bz2_d.pyd", "_ctypes_d.pyd",
    "_decimal_d.pyd", "_elementtree_d.pyd", "_hashlib_d.pyd", "_lzma_d.pyd", "_message.pyd",
    "_multiprocessing_d.pyd", "_native.cp314-win_amd64.pyd", "_overlapped_d.pyd", "_pydantic_core.cp314-win_amd64.pyd",
    "_queue_d.pyd", "_remote_debugging_d.pyd", "_sentencepiece.cp314-win_amd64.pyd", "_socket_d.pyd",
    "_sqlite3_d.pyd", "_ssl_d.pyd", "_tiktoken.cp314-win_amd64.pyd", "_uuid_d.pyd", "_wmi_d.pyd",
    "_zoneinfo_d.pyd", "_zstd_d.pyd", "manage.cp314-win_amd64.pyd", "Store.Purchase.Component.winmd",
    "WinStore.Tasks.winmd", "StoreDesktopExtension.exe", "StoreMcpServer.exe", "DuckDns.exe", "unins000.exe"
)

$unblockedCount = 0

foreach ($hive in $hives) {
    foreach ($e in $entries) {
        $targetKey = "$hive\$e"
        if (Test-Path $targetKey) {
            $prop = Get-ItemProperty -Path $targetKey -ErrorAction SilentlyContinue
            if ($prop.Debugger -eq "systray.exe") {
                Remove-Item -Path $targetKey -Recurse -Force -ErrorAction SilentlyContinue
                $unblockedCount++
                Write-Host "Unblocked IFEO: $targetKey" -ForegroundColor Green
            }
        }
    }
}

Write-Host "`nCompleted! Successfully unblocked $unblockedCount IFEO trap entries." -ForegroundColor Cyan
