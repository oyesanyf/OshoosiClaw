# Deep YARA Hardener v3 - Handles within-file duplicates and unknown identifiers
# Targets ALL yar directories including any nested signature_base

param(
    [string]$YaraDir = "yara"
)

$GlobalSeenRules = @{}
$GlobalFixedCount = 0

Write-Host "Starting deep YARA sanitization v3 (within-file + cross-file dedup + identifier fixes)..." -ForegroundColor Cyan

function Escape-YaraRegexLine {
    param([string]$Line)
    # If the line has a regex pattern (contains / after = or :) with unescaped { not followed by digit
    # We need to escape { that are NOT valid YARA repetitions like {3}, {1,5}
    $result = $Line
    # Find regex portions between slashes -- do a simple string scan
    # Strategy: for regex strings ($var = /.../) escape { not followed by digit or \
    if ($result -match '\$\w+\s*=\s*/') {
        # Replace { that are NOT preceded by \ and NOT followed by a digit (i.e., not a counted repetition)
        $result = [regex]::Replace($result, '(?<!\\)\{(?!\d)', '\{')
        # Also escape } that are not preceded by digit or * (closing a repetition)
        $result = [regex]::Replace($result, '(?<!\d|,|\*)\}(?!\d)', '\}')
    }
    return $result
}

$Files = Get-ChildItem -Path $YaraDir -Filter "*.yar" -Recurse -ErrorAction SilentlyContinue
$Files += Get-ChildItem -Path $YaraDir -Filter "*.yara" -Recurse -ErrorAction SilentlyContinue

foreach ($File in $Files) {
    # Skip index files
    if ($File.Name -like "index.yar" -or $File.Name -like "*_index.yar") { continue }
    
    $FilePath = $File.FullName
    try {
        $RawBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $Content = [System.Text.Encoding]::UTF8.GetString($RawBytes)
    } catch {
        continue
    }

    $Lines = $Content -split "`r?`n"
    $NewLines = @()
    $Changed = $false
    
    # Per-file duplicate tracking (for within-file duplicates)
    $FileSeenRules = @{}

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $Line = $Lines[$i]
        $Trimmed = $Line.Trim()
        $NewLine = $Line

        # 1. Comment out androguard imports
        if ($Trimmed -match '^import\s+["'']androguard["'']' -and -not $Trimmed.StartsWith("//")) {
            $NewLine = "// $Line"
            $Changed = $true
        }

        # 2a. Within-file Rule Deduplication (same rule appears twice in same file)
        if ($NewLine -match '^\s*(global\s+|private\s+)?rule\s+([A-Za-z0-9_]+)') {
            $Name = $Matches[2]
            
            if ($FileSeenRules.ContainsKey($Name)) {
                # Rename this declaration
                $DupIdx = $FileSeenRules[$Name]
                $NewName = "${Name}_v${DupIdx}"
                $FileSeenRules[$Name] += 1
                $NewLine = $NewLine -replace "\brule\s+$([regex]::Escape($Name))\b", "rule $NewName"
                Write-Host "  [within-file] Renamed duplicate '$Name' -> '$NewName' in $($File.Name)" -ForegroundColor DarkGray
                $Changed = $true
            } else {
                $FileSeenRules[$Name] = 2
            }

            # 2b. Cross-file deduplication (same rule appears in a different file)
            # Note: after within-file rename, get the current rule name
            $CurrentName = if ($NewLine -match '^\s*(global\s+|private\s+)?rule\s+([A-Za-z0-9_]+)') { $Matches[2] } else { $Name }
            if ($GlobalSeenRules.ContainsKey($CurrentName)) {
                $DupIdx = $GlobalSeenRules[$CurrentName]
                $NewGlobalName = "${CurrentName}_dup${DupIdx}"
                $GlobalSeenRules[$CurrentName] += 1
                $NewLine = $NewLine -replace "\brule\s+$([regex]::Escape($CurrentName))\b", "rule $NewGlobalName"
                Write-Host "  [cross-file]  Renamed '$CurrentName' -> '$NewGlobalName' in $($File.Name)" -ForegroundColor DarkGray
                $Changed = $true
            } else {
                $GlobalSeenRules[$CurrentName] = 2
            }
        }

        # 3. Comment out lines using unknown identifiers: filename, filepath, extension
        if (-not $Trimmed.StartsWith("//")) {
            $HasUnknownId = (
                ($Trimmed -match '\bfilename\s*(==|matches|contains)') -or
                ($Trimmed -match '\bfilepath\s*(==|matches|contains)') -or
                ($Trimmed -match '\bextension\s*(==|matches|contains)')
            )
            if ($HasUnknownId) {
                $NewLine = "// $Line  /* Disabled: unknown identifier (filename/filepath/extension not in yara-x) */"
                $Changed = $true
            }
        }

        # 4. Fix pe.exports type mismatch
        if ($Line.Contains('pe.exports') -and $Line.Contains('& pe.characteristics')) {
            $NewLine = $NewLine -replace '& pe\.characteristics', 'and pe.characteristics != 0'
            $Changed = $true
        }

        # 5. Regex curly-brace hardening (unescaped { in regex patterns)
        if ($Trimmed -match '\$\w+\s*=\s*/' -and $Trimmed.Contains('{') -and -not $Trimmed.Contains('\{')) {
            if ($Trimmed -notmatch '\{\d+(,\d*)?\}') {
                $NewLine = Escape-YaraRegexLine -Line $NewLine
                if ($NewLine -ne $Line) { $Changed = $true }
            }
        }

        $NewLines += $NewLine
    }

    if ($Changed) {
        try {
            $OutputText = $NewLines -join "`r`n"
            $OutputBytes = [System.Text.Encoding]::UTF8.GetBytes($OutputText)
            [System.IO.File]::WriteAllBytes($FilePath, $OutputBytes)
            $GlobalFixedCount++
        } catch {
            Write-Host "  ERROR writing $FilePath : $_" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Done. Fixed $GlobalFixedCount files." -ForegroundColor Green
