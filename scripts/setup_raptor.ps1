<#
.SYNOPSIS
    Bootstraps and configures the RAPTOR Autonomous Offensive/Defensive Research Framework
    (https://github.com/gadievron/raptor & danielcuthbert/raptor:latest) for local repository
    and web application security scanning.

.DESCRIPTION
    1. Clones https://github.com/gadievron/raptor.git into $RaptorRoot (default: D:\docker\raptor) if missing.
    2. Configures models.json for local Ollama inference over host.docker.internal:11434.
    3. Patches core/llm/egress.py and core/llm/detection.py so host.docker.internal bypasses the
       CONNECT-only egress proxy.
    4. Installs Invoke-RaptorScan.ps1 into $RaptorRoot.
    5. Pulls the official Docker image (danielcuthbert/raptor:latest) and optional Ollama model.
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$RaptorRoot = "D:\docker\raptor",

    [Parameter(Mandatory=$false)]
    [string]$DockerImage = "danielcuthbert/raptor:latest",

    [Parameter(Mandatory=$false)]
    [string]$OllamaModel = "fenkohq/foundation-sec-8b:latest",

    [Parameter(Mandatory=$false)]
    [switch]$SkipDockerPull,

    [Parameter(Mandatory=$false)]
    [switch]$PullOllamaModel
)

$ErrorActionPreference = "Stop"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  RAPTOR Security Framework Bootstrap & Installer" -ForegroundColor Cyan
Write-Host "  Source : https://github.com/gadievron/raptor" -ForegroundColor Cyan
Write-Host "  Image  : $DockerImage" -ForegroundColor Cyan
Write-Host "  Target : $RaptorRoot" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

$ParentDir = Split-Path -Path $RaptorRoot -Parent
if ($ParentDir -and -not (Test-Path $ParentDir)) {
    New-Item -ItemType Directory -Path $ParentDir -Force | Out-Null
}

# 1. Clone or verify RAPTOR repository
if (-not (Test-Path (Join-Path $RaptorRoot "raptor.py"))) {
    Write-Host "[*] Cloning https://github.com/gadievron/raptor.git into $RaptorRoot..." -ForegroundColor Yellow
    git clone https://github.com/gadievron/raptor.git $RaptorRoot
} else {
    Write-Host "[+] RAPTOR repository already present at $RaptorRoot" -ForegroundColor Green
}

# 2. Write models.json configured for host.docker.internal Ollama
$ModelsJsonPath = Join-Path $RaptorRoot "models.json"
$ModelsJson = @"
{
  "models": [
    {
      "provider": "ollama",
      "model": "fenkohq/foundation-sec-8b:latest",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "mistral",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "qwen2.5:32b",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "deepseek-r1:32b",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "qwen2.5:7b",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    }
  ]
}
"@
Set-Content -Path $ModelsJsonPath -Value $ModelsJson -Encoding UTF8
Write-Host "[+] Configured $ModelsJsonPath for local Ollama (host.docker.internal:11434)" -ForegroundColor Green

# 3. Ensure host.docker.internal is in _LOCAL_BYPASS (core/llm/egress.py & detection.py)
$EgressPy = Join-Path $RaptorRoot "core\llm\egress.py"
if (Test-Path $EgressPy) {
    $EgressTxt = Get-Content -Path $EgressPy -Raw -Encoding UTF8
    if ($EgressTxt -notmatch "host\.docker\.internal") {
        $EgressTxt = $EgressTxt.Replace(
            '"localhost", "127.0.0.1", "::1", "0.0.0.0",',
            '"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal",'
        )
        Set-Content -Path $EgressPy -Value $EgressTxt -NoNewline -Encoding UTF8
        Write-Host "[+] Patched $EgressPy with host.docker.internal loopback bypass" -ForegroundColor Green
    }
}

$DetectionPy = Join-Path $RaptorRoot "core\llm\detection.py"
if (Test-Path $DetectionPy) {
    $DetTxt = Get-Content -Path $DetectionPy -Raw -Encoding UTF8
    if ($DetTxt -notmatch "host\.docker\.internal") {
        $DetTxt = $DetTxt.Replace(
            'if host in ("localhost", "0.0.0.0"):',
            'if host in ("localhost", "0.0.0.0", "host.docker.internal"):'
        )
        Set-Content -Path $DetectionPy -Value $DetTxt -NoNewline -Encoding UTF8
        Write-Host "[+] Patched $DetectionPy with host.docker.internal local host recognition" -ForegroundColor Green
    }
}

# 4. Copy Invoke-RaptorScan.ps1 into $RaptorRoot
$LocalInvoke = Join-Path $PSScriptRoot "Invoke-RaptorScan.ps1"
$DestInvoke = Join-Path $RaptorRoot "Invoke-RaptorScan.ps1"
if (Test-Path $LocalInvoke) {
    Copy-Item -Path $LocalInvoke -Destination $DestInvoke -Force
    Write-Host "[+] Installed $DestInvoke" -ForegroundColor Green
}

# 5. Pull Docker image if not skipped
if (-not $SkipDockerPull) {
    $ErrorActionPreference = "SilentlyContinue"
    $ImgId = (& docker image inspect $DockerImage --format '{{.Id}}' 2>$null)
    $ErrorActionPreference = "Continue"
    if ([string]::IsNullOrWhiteSpace($ImgId)) {
        Write-Host "[*] Pulling RAPTOR Docker image ($DockerImage)..." -ForegroundColor Yellow
        & docker pull $DockerImage
    } else {
        Write-Host "[+] Docker image $DockerImage is ready ($($ImgId.Substring(0, [Math]::Min(18, $ImgId.Length))))" -ForegroundColor Green
    }
}

# 6. Optionally pull default Ollama model
if ($PullOllamaModel) {
    Write-Host "[*] Pulling Ollama security model ($OllamaModel)..." -ForegroundColor Yellow
    & ollama pull $OllamaModel
}

Write-Host "`n[+] RAPTOR setup complete! Run a full scan anytime with:" -ForegroundColor Green
Write-Host "    powershell -ExecutionPolicy Bypass -File `"$DestInvoke`" -TargetPath `"<repo_path>`" -Mode all" -ForegroundColor Cyan
