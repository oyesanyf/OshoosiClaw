$ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
Get-ChildItem -Path $ifeoPath | ForEach-Object {
    $item = $_
    $prop = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
    if ($prop -and $prop.Debugger -and ($prop.Debugger -like "*systray*" -or $prop.Debugger -like "*osoosi*")) {
        Write-Host "Found IFEO hijacking on: $($item.PSChildName) -> $($prop.Debugger)"
        try {
            Remove-ItemProperty -Path $item.PSPath -Name "Debugger" -Force -ErrorAction SilentlyContinue
            Write-Host "  Removed Debugger property from $($item.PSChildName)"
        } catch {
            Write-Host "  Failed to remove: $_"
        }
    }
}
