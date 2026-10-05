<#
.SYNOPSIS
    Launches or controls the OpenỌ̀ṣọ́ọ̀sì LangGraph Defense Swarm microservice.
.PARAMETER Action
    Command action to execute: 'start', 'status', 'investigate', 'approvals' (default: start)
.PARAMETER Port
    HTTP port to bind (default: 4002)
#>
param(
    [ValidateSet("start", "status", "investigate", "approvals")]
    [string]$Action = "start",
    [int]$Port = 4002,
    [int]$Pid = 0,
    [string]$ProcessName = "suspicious.exe",
    [string]$CommandLine = ""
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONPATH = "$ScriptDir\src;$env:PYTHONPATH"

switch ($Action) {
    "start" {
        Write-Host "[*] Starting Defense Swarm service on 127.0.0.1:$Port..." -ForegroundColor Cyan
        python -m defense_swarm.cli start --host 127.0.0.1 --port $Port
    }
    "status" {
        python -m defense_swarm.cli status --url "http://127.0.0.1:$Port"
    }
    "investigate" {
        python -m defense_swarm.cli investigate --url "http://127.0.0.1:$Port" --pid $Pid --name $ProcessName --cmd $CommandLine
    }
    "approvals" {
        python -m defense_swarm.cli approvals --url "http://127.0.0.1:$Port"
    }
}
