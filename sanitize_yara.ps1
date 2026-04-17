# Oshoosi YARA Rule Sanitizer (Force Fix v2)
$yara_dir = "yara"
if (-Not (Test-Path $yara_dir)) {
    Write-Host "YARA directory not found at $yara_dir" -ForegroundColor Red
    exit 1
}

Write-Host "Searching for .yar files in $yara_dir..."
$yar_files = Get-ChildItem -Path $yara_dir -Filter "*.yar" -Recurse

foreach ($file in $yar_files) {
    try {
        $content = [System.IO.File]::ReadAllText($file.FullName)
    } catch {
        continue
    }
    $changed = $false
    
    # 1. Comment out androguard imports
    if ($content -match 'import\s+["'']androguard["'']') {
        $content = $content -replace '(import\s+["'']androguard["''])', '// $1'
        $changed = $true
    }
    
    # 2. Fix pe.exports & pe.characteristics type mismatch
    if ($content.Contains('pe.exports("Crash")') -or $content.Contains('pe.exports("crash")')) {
        if ($content.Contains('& pe.characteristics')) {
            $content = $content.Replace('pe.exports("Crash")', 'pe.exports("Crash") != false')
            $content = $content.Replace('pe.exports("crash")', 'pe.exports("crash") != false')
            $content = $content.Replace('& pe.characteristics', 'and pe.characteristics != 0')
            $changed = $true
        }
    }
    
    # 3. Rename duplicate Maze rules in RANSOM_Maze.yar
    if ($file.Name -eq "RANSOM_Maze.yar") {
        if ($content.Contains('rule Maze')) {
            $first = $true
            $new_lines = @()
            foreach ($line in $content -split "`r?`n") {
                if ($line.Trim().StartsWith('rule Maze')) {
                    if ($first) {
                        $first = $false
                        $new_lines += $line
                    } else {
                        $new_lines += ($line -replace 'rule Maze', 'rule Maze_Duplicate')
                        $changed = $true
                    }
                } else {
                    $new_lines += $line
                }
            }
            $content = $new_lines -join "`r`n"
        }
    }
    
    # 4. Fix empty regex matches (e.g. /BADD|/)
    if ($content.Contains('|/')) {
        $content = $content.Replace('|/', '/')
        $changed = $true
    }
    
    # 5. Fix unrecognized escapes (\V, \P)
    if ($content.Contains('\V') -and -not $content.Contains('\\V')) {
        $content = $content.Replace('\V', '\\V')
        $changed = $true
    }
    if ($content.Contains('\P') -and -not $content.Contains('\\P')) {
        $content = $content.Replace('\P', '\\P')
        $changed = $true
    }

    # 6. Fix unclosed counted repetition ({)
    if ($content.Contains('? {/')) {
        $content = $content.Replace('? {/', '? \{/')
        $changed = $true
    }
    if ($content.Contains('?{/')) {
        $content = $content.Replace('?{/', '?\{/')
        $changed = $true
    }

    # 7. Comment out includes in index files
    if ($file.Name -match 'index\.yar$') {
        $new_lines = @()
        foreach ($line in $content -split "`r?`n") {
            if ($line.Trim().StartsWith("include") -and -not $line.Trim().StartsWith("//")) {
                $new_lines += "// $line"
                $changed = $true
            } else {
                $new_lines += $line
            }
        }
        $content = $new_lines -join "`r`n"
    }

    if ($changed) {
        Write-Host "Fixed: $($file.FullName)" -ForegroundColor Cyan
        [System.IO.File]::WriteAllText($file.FullName, $content)
    }
}

Write-Host "Sanitization complete." -ForegroundColor Green
