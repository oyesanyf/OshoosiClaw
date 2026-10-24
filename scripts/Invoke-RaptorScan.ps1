param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$TargetPath = (Get-Location).Path,

    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "scan", "agentic", "crypto", "sca", "openant", "describe", "web")]
    [string]$Mode = "all",

    [Parameter(Mandatory=$false)]
    [string]$Url = "",

    [Parameter(Mandatory=$false)]
    [string]$Model = "ollama/fenkohq/foundation-sec-8b:latest",

    [Parameter(Mandatory=$false)]
    [string]$PolicyGroups = "",

    [Parameter(Mandatory=$false)]
    [switch]$IncludeCodeQL,

    [Parameter(Mandatory=$false)]
    [string]$RaptorRoot = "D:\docker\raptor"
)

$ErrorActionPreference = "Stop"

if ($Model -and ($Model -notmatch "^(ollama|anthropic|openai|gemini|google|mistral|cohere|bedrock|openrouter|together|groq|fireworks|deepinfra)/") -and ($Model -notmatch "^(claude-|gpt-|o1-|o3-|o4-|gemini-)")) {
    $Model = "ollama/$Model"
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Auto-bootstrap RAPTOR if $RaptorRoot is missing
if (-not (Test-Path -Path (Join-Path $RaptorRoot "raptor.py"))) {
    $SetupScript = Join-Path $PSScriptRoot "setup_raptor.ps1"
    if (Test-Path $SetupScript) {
        Write-Host "[*] RAPTOR not found at $RaptorRoot. Bootstrapping via $SetupScript..." -ForegroundColor Yellow
        & powershell -ExecutionPolicy Bypass -File $SetupScript -RaptorRoot $RaptorRoot
    }
}

if ($Url -or ($TargetPath -match "^https?://") -or ($Mode -eq "web")) {
    $TargetUrl = if ($Url) { $Url } elseif ($TargetPath -match "^https?://") { $TargetPath } else { "https://$TargetPath" }
    $ResolvedTarget = (Get-Location).Path
    $UriObj = [System.Uri]$TargetUrl
    $ProjectSlug = "web_" + ($UriObj.Host -replace '[\.:]', '_')
    $Mode = "web"
    $ContainerTargetUrl = $TargetUrl -replace '(?i)://(127\.0\.0\.1|localhost)(:\d+)?', '://host.docker.internal$2'
} else {
    $ResolvedTarget = (Resolve-Path -Path $TargetPath).Path
    $ProjectSlug = (Split-Path -Path $ResolvedTarget -Leaf) -replace '\s+', '_'
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$HostOutDirName = "${ProjectSlug}_${Mode}_${Timestamp}"
$HostOutDir = Join-Path -Path $RaptorRoot -ChildPath "out\$HostOutDirName"

if (-not (Test-Path -Path $HostOutDir)) {
    New-Item -ItemType Directory -Path $HostOutDir -Force | Out-Null
}

$ContainerTmpOut = "/tmp/raptor_${ProjectSlug}_${Timestamp}"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  RAPTOR Autonomous Security Scanner (Antigravity Integration)" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
if ($Mode -eq "web") {
    Write-Host "  [*] Target Host URL: $TargetUrl" -ForegroundColor White
} else {
    Write-Host "  [*] Target Project : $ResolvedTarget" -ForegroundColor White
}
Write-Host "  [*] Scan Mode      : $Mode" -ForegroundColor White
if ($Mode -eq "agentic" -or $Mode -eq "all") {
    Write-Host "  [*] Ollama Model   : $Model" -ForegroundColor White
}
Write-Host "  [*] Output Folder  : $HostOutDir" -ForegroundColor Green
Write-Host "====================================================================`n" -ForegroundColor Cyan

$ContainerRepo = "/tmp/raptor_repo_${Timestamp}"
$StageCmd = "mkdir -p '$ContainerRepo' && tar -C /workspaces/target --exclude='./target' --exclude='./target_alt' --exclude='./target_ci_check' --exclude='./.git' --exclude='./sigma' --exclude='./rules' --exclude='./yara' --exclude='./tmp_stix' --exclude='./backups' --exclude='./cache' --exclude='./quarantine' --exclude='./models' --exclude='./database' --exclude='./logs' --exclude='./runs' --exclude='./bin' --exclude='./deploy' --exclude='./node_modules' -cf - . | tar -C '$ContainerRepo' -xf -"

$SyncOut = "cp -r $ContainerTmpOut/* /workspaces/raptor/out/$HostOutDirName/ 2>/dev/null || true"

switch ($Mode) {
    "all" {
        $CodeQLFlag = if ($IncludeCodeQL) { "--codeql" } else { "--no-codeql" }
        $InnerCmd = "$StageCmd ; python3 raptor.py doctor | tee $ContainerTmpOut/doctor.txt || true ; $SyncOut ; python3 raptor.py describe --target $ContainerRepo | tee $ContainerTmpOut/describe.txt || true ; $SyncOut ; python3 raptor.py scan --repo $ContainerRepo --out $ContainerTmpOut/scan ; $SyncOut ; python3 raptor.py scan --repo $ContainerRepo --policy-groups crypto --out $ContainerTmpOut/crypto ; $SyncOut ; python3 raptor.py sca --repo $ContainerRepo --out $ContainerTmpOut/sca || true ; $SyncOut ; python3 raptor.py openant --repo $ContainerRepo --forecast --out $ContainerTmpOut/openant || true ; $SyncOut ; python3 raptor.py agentic --repo $ContainerRepo --sarif $ContainerTmpOut/scan/combined.sarif --model $Model --accept-weakened-defenses --max-findings 10 --no-exploits --phase-timeout 0 $CodeQLFlag --out $ContainerTmpOut/agentic || true ; $SyncOut"
    }
    "web" {
        $InnerCmd = "python3 raptor.py web --url $ContainerTargetUrl --out $ContainerTmpOut"
    }
    "describe" {
        $InnerCmd = "$StageCmd ; python3 raptor.py describe --target $ContainerRepo"
    }
    "crypto" {
        $InnerCmd = "$StageCmd ; python3 raptor.py scan --repo $ContainerRepo --policy-groups crypto --out $ContainerTmpOut"
    }
    "sca" {
        $InnerCmd = "$StageCmd ; python3 raptor.py sca --repo $ContainerRepo --out $ContainerTmpOut"
    }
    "openant" {
        $InnerCmd = "$StageCmd ; python3 raptor.py openant --repo $ContainerRepo --forecast --out $ContainerTmpOut"
    }
    "agentic" {
        $CodeQLFlag = if ($IncludeCodeQL) { "--codeql" } else { "--no-codeql" }
        $PgFlag = if ($PolicyGroups) { "--policy-groups $PolicyGroups" } else { "" }
        $InnerCmd = "$StageCmd ; python3 raptor.py agentic --repo $ContainerRepo --model $Model --accept-weakened-defenses --max-findings 10 --no-exploits --phase-timeout 0 $CodeQLFlag $PgFlag --out $ContainerTmpOut"
    }
    default {
        $PgFlag = if ($PolicyGroups) { "--policy-groups $PolicyGroups" } else { "" }
        $InnerCmd = "$StageCmd ; python3 raptor.py scan --repo $ContainerRepo $PgFlag --out $ContainerTmpOut"
    }
}

$ErrorActionPreference = "SilentlyContinue"
$ServerVer = (& docker version --format '{{.Server.Version}}' 2>$null)
$DockerReady = (-not [string]::IsNullOrWhiteSpace($ServerVer))
if (-not $DockerReady) {
    $DockerDesktopCandidates = @(
        "$env:LOCALAPPDATA\Programs\DockerDesktop\Docker Desktop.exe",
        "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    )
    foreach ($Candidate in $DockerDesktopCandidates) {
        if (Test-Path $Candidate) {
            Write-Host "  [*] Starting Docker Desktop daemon ($Candidate)..." -ForegroundColor Yellow
            Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "`"$Candidate`"" } | Out-Null
            break
        }
    }
    for ($w = 0; $w -lt 45; $w++) {
        Start-Sleep -Seconds 2
        $ServerVer = (& docker version --format '{{.Server.Version}}' 2>$null)
        if (-not [string]::IsNullOrWhiteSpace($ServerVer)) {
            $DockerReady = $true
            break
        }
    }
}
$ErrorActionPreference = "Continue"

$BashScript = "mkdir -p '$ContainerTmpOut' ; $InnerCmd ; EXIT_CODE=`$? ; if [ -d '$ContainerTmpOut' ]; then $SyncOut ; fi ; exit `$EXIT_CODE"

docker run --rm `
    --add-host=host.docker.internal:host-gateway `
    -v "${RaptorRoot}:/workspaces/raptor" `
    -v "${ResolvedTarget}:/workspaces/target" `
    -e OLLAMA_HOST="http://host.docker.internal:11434" `
    -e RAPTOR_ALLOW_DEGRADED_UNTRUSTED="1" `
    danielcuthbert/raptor:latest `
    bash -c $BashScript

Write-Host "`n[+] Scan finished! Reports saved to: $HostOutDir" -ForegroundColor Green
