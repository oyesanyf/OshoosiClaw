$ErrorActionPreference = "Continue"
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Deleting all 25 forked Awesome-List repositories from oyesanyf" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$scopes = gh auth status 2>&1 | Out-String
if ($scopes -notmatch "delete_repo") {
    Write-Host "[*] Requesting 'delete_repo' permission from GitHub CLI (one-time browser confirmation)..." -ForegroundColor Yellow
    gh auth refresh -h github.com -s delete_repo
}

$awesomeForks = @(
    "awesome-rust-security",
    "awesome-openclaw",
    "awesome-openclaw-skills",
    "awesome-agent-skills-security",
    "awesome-agent-control-plane",
    "awesome-claw",
    "awesome-ai-agents",
    "awesome-ai-security-tools",
    "awesome-ai-security",
    "BlueTeam-Tools",
    "awesome-yara",
    "awesome-reversing",
    "awesome-forensics",
    "awesome_Threat-Hunting",
    "awesome-aya",
    "reverse-engineering",
    "awesome-incident-response",
    "awesome-security",
    "awesome-llm-security",
    "awesome-detection-engineering",
    "awesome-ebpf",
    "awesome-cybersecurity-blueteam",
    "awesome-threat-detection",
    "awesome-endpoint-detection-and-response",
    "awesome-claws"
)

foreach ($repo in $awesomeForks) {
    gh repo delete "oyesanyf/$repo" --yes
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[DELETED] https://github.com/oyesanyf/$repo" -ForegroundColor Green
    } else {
        Write-Host "[SKIPPED/ERR] oyesanyf/$repo" -ForegroundColor Red
    }
}
Write-Host "[+] Done! All forked awesome-list repositories removed." -ForegroundColor Green
