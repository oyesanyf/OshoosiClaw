<#
.SYNOPSIS
    OpenỌ̀ṣọ́ọ̀sì LangGraph Autonomous Defense Swarm PowerShell Wrapper
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgsList
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$SrcDir = Join-Path $RootDir "src"

$env:PYTHONPATH = "$SrcDir;$env:PYTHONPATH"

& python -m defense_swarm.cli @ArgsList
