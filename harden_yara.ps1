# Deep YARA Hardener v4 - Semantic-Preserving YARA Rule Sanitizer & Verifier
# Delegates to harden_yara.py to ensure:
#   1. Zero corruption of double-quoted string literals ($s = "...") containing `/` and `{...}`
#   2. Token-aware escaping of non-quantifier `{` and `}` inside `/regex/` bodies only
#   3. Exact-token duplicate rule renaming (within-file & cross-file)
#   4. Surgical external-variable condition stripping & zero vacuous `condition: false` rules

param(
    [string]$YaraDir = "yara"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyScript = Join-Path $ScriptDir "harden_yara.py"

if (Test-Path $PyScript) {
    & python $PyScript $YaraDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "harden_yara.py reported verification errors (exit code $LASTEXITCODE)."
        exit $LASTEXITCODE
    }
    exit 0
}

Write-Error "harden_yara.py not found at $PyScript"
exit 1
