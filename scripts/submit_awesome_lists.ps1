<#
.SYNOPSIS
    OshoosiClaw 4-Vertical Awesome Lists Traction & PR Submission Orchestrator
.DESCRIPTION
    Wraps scripts/submit_awesome_lists.py to inspect, generate tailored descriptions,
    dry-run README insertions, or execute automated forked Pull Requests across all 4 verticals.
#>
param(
    [switch]$List,
    [switch]$VerifyRemote,
    [switch]$GenerateBundle,
    [switch]$Submit,
    [int]$Vertical = 0,
    [string]$Repo = "",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "submit_awesome_lists.py"

$pyArgs = @($scriptPath)
if ($List) { $pyArgs += "--list" }
if ($VerifyRemote) { $pyArgs += "--verify-remote" }
if ($GenerateBundle) { $pyArgs += "--generate-bundle" }
if ($Submit) { $pyArgs += "--submit" }
if ($Vertical -ge 1 -and $Vertical -le 4) { $pyArgs += @("--vertical", "$Vertical") }
if ($Repo -ne "") { $pyArgs += @("--repo", $Repo) }
if ($Execute) { $pyArgs += "--execute" }

& python @pyArgs
if ($LASTEXITCODE -ne 0) {
    throw "submit_awesome_lists.py failed with exit code $LASTEXITCODE"
}
