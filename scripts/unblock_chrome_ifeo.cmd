@echo off
echo [*] Purging false-positive Osoosi IFEO Debugger=systray.exe registry hooks...
C:\Windows\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\systray.exe" /v Debugger /f >nul 2>&1
C:\Windows\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe" /v Debugger /f >nul 2>&1
C:\Windows\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v Debugger /f >nul 2>&1
C:\Windows\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\git.exe" /v Debugger /f >nul 2>&1
C:\Windows\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sh.exe" /v Debugger /f >nul 2>&1
C:\Windows\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sqlite3.exe" /v Debugger /f >nul 2>&1

for /f "tokens=*" %%K in ('C:\Windows\System32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger 2^>nul ^| C:\Windows\System32\findstr.exe /i "HKEY_LOCAL_MACHINE\\"') do (
    C:\Windows\System32\reg.exe query "%%K" /v Debugger 2>nul | C:\Windows\System32\findstr.exe /i "systray.exe" >nul && (
        echo [+] Removing IFEO hook: %%K
        C:\Windows\System32\reg.exe delete "%%K" /v Debugger /f >nul 2>&1
    )
)
echo [+] All IFEO Debugger=systray.exe hooks removed. Chrome and all tools are unblocked!
