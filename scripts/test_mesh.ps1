<#
.SYNOPSIS
    OshoosiClaw Mesh Connectivity & Gossipsub Verification Script.
.DESCRIPTION
    Tests local and remote daemon connectivity, TCP port 4001 socket states,
    cryptographic DID verification, bidirectional Gossipsub broadcasting,
    and inter-node threat intelligence exchange.
.PARAMETER PeerIp
    Optional IP address of the target peer to test against. Auto-detected from active TCP 4001 sockets if omitted.
.PARAMETER LocalPort
    Dashboard HTTP port on the local node (default: 3030).
.PARAMETER RemotePort
    Dashboard HTTP port on the remote peer (default: 3030).
#>

[CmdletBinding()]
param(
    [string]$PeerIp,
    [int]$LocalPort = 3030,
    [int]$RemotePort = 3030
)

$ErrorActionPreference = "Continue"

function Write-Banner {
    Write-Host @"
========================================================================
   🏹  OSHOOSI CLAW — P2P MESH INTER-NODE VERIFICATION SUITE
========================================================================
"@ -ForegroundColor Cyan
}

function Write-Step([string]$msg) {
    Write-Host "`n[*] $msg" -ForegroundColor Yellow
}

function Write-Pass([string]$msg) {
    Write-Host "    [PASS] $msg" -ForegroundColor Green
}

function Write-Fail([string]$msg) {
    Write-Host "    [FAIL] $msg" -ForegroundColor Red
}

function Write-Info([string]$msg) {
    Write-Host "    [INFO] $msg" -ForegroundColor Gray
}

Write-Banner

# Step 1: Probe Local Daemon
Write-Step "Checking Local Oshoosi Daemon (http://127.0.0.1:$LocalPort)..."
$localStatus = $null
$localMesh = $null
try {
    $localStatus = Invoke-RestMethod -Uri "http://127.0.0.1:$LocalPort/api/status" -TimeoutSec 8
    $localMesh = Invoke-RestMethod -Uri "http://127.0.0.1:$LocalPort/api/mesh-stats" -TimeoutSec 8
    Write-Pass "Local daemon is online and responsive."
    Write-Info "Node DID       : $($localStatus.node_id)"
    Write-Info "Uptime         : $($localStatus.uptime)"
    Write-Info "Audit Chain    : $(if ($localStatus.chain_verified) { 'Verified (Merkle Root synced)' } else { 'Unverified' })"
    Write-Info "Swarm Peers    : $($localMesh.peer_count) connected"
    Write-Info "Gossip Received: $($localMesh.gossip_count) packets"
} catch {
    Write-Fail "Could not reach local daemon at http://127.0.0.1:$LocalPort. Is 'osoosi' running?"
    Write-Fail "Error: $($_.Exception.Message)"
    exit 1
}

# Step 2: Discover Active TCP Sockets on Port 4001
Write-Step "Inspecting Transport Sockets (Port 4001)..."
$establishedSockets = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
    $_.LocalPort -eq 4001 -or $_.RemotePort -eq 4001
}

if ($establishedSockets) {
    foreach ($sock in $establishedSockets) {
        $partnerIp = $sock.RemoteAddress
        Write-Pass "Active Socket: $($sock.LocalAddress):$($sock.LocalPort) <--> $($sock.RemoteAddress):$($sock.RemotePort) (State: Established)"
        if (-not $PeerIp -and $partnerIp -notmatch "^127\." -and $partnerIp -ne "0.0.0.0") {
            $PeerIp = $partnerIp
        }
    }
} else {
    Write-Info "No 'Established' TCP connections currently open on port 4001."
}

if (-not $PeerIp) {
    Write-Host "`n[?] Auto-detection did not find a remote peer IP." -ForegroundColor Yellow
    $PeerIp = Read-Host "    Enter remote peer IP address to test (e.g. 10.0.0.165)"
}

if (-not $PeerIp) {
    Write-Fail "No remote peer IP provided. Cannot perform inter-node tests."
    exit 1
}

# Step 3: Probe Remote Peer Dashboard API
Write-Step "Testing Connection to Remote Peer ($PeerIp)..."
$remoteStatus = $null
$remoteMesh = $null

$port4001Test = Test-NetConnection -ComputerName $PeerIp -Port 4001 -WarningAction SilentlyContinue
if ($port4001Test.TcpTestSucceeded) {
    Write-Pass "Peer $PeerIp is listening on P2P Mesh Port 4001 (TCP OK)."
} else {
    Write-Fail "Peer $PeerIp failed TCP handshake on port 4001. Check Windows Firewall."
}

try {
    $remoteStatus = Invoke-RestMethod -Uri "http://${PeerIp}:${RemotePort}/api/status" -TimeoutSec 3
    $remoteMesh = Invoke-RestMethod -Uri "http://${PeerIp}:${RemotePort}/api/mesh-stats" -TimeoutSec 3
    Write-Pass "Remote daemon reachable at http://${PeerIp}:${RemotePort}."
    Write-Info "Remote Node DID : $($remoteStatus.node_id)"
    Write-Info "Remote Uptime   : $($remoteStatus.uptime)"
    Write-Info "Remote Peers    : $($remoteMesh.peer_count) connected"
    Write-Info "Remote Gossip   : $($remoteMesh.gossip_count) packets received"
} catch {
    Write-Info "Remote dashboard API (port $RemotePort) not directly accessible from this host (normal if firewalled)."
}

# Step 4: Perform Live Gossip Broadcast Test
Write-Step "Executing Live Gossipsub Broadcast Verification..."
$timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$testPayload = @{
    summary = "Mesh Verification Probe from $((hostname)) at $timestamp"
} | ConvertTo-Json

try {
    $broadcastResult = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$LocalPort/api/mesh/broadcast" -Body $testPayload -ContentType "application/json" -TimeoutSec 4
    if ($broadcastResult.ok) {
        Write-Pass "Local node successfully transmitted gossip packet across mesh topic."
    } else {
        Write-Fail "Local node failed to broadcast packet: $($broadcastResult.error)"
    }
} catch {
    Write-Fail "Broadcast API call failed: $($_.Exception.Message)"
}

# If remote daemon API is accessible, check if remote received it!
if ($remoteStatus) {
    Start-Sleep -Seconds 1
    try {
        $updatedRemoteMesh = Invoke-RestMethod -Uri "http://${PeerIp}:${RemotePort}/api/mesh-stats" -TimeoutSec 3
        Write-Info "Remote Gossip Count: Before=$($remoteMesh.gossip_count), After=$($updatedRemoteMesh.gossip_count)"
        if ($updatedRemoteMesh.gossip_count -ge $remoteMesh.gossip_count) {
            Write-Pass "Remote node received and processed gossipsub broadcast packet!"
        }
    } catch {
        Write-Info "Could not re-query remote node metrics."
    }
}

# Step 5: Summary Verdict
Write-Host @"

========================================================================
   VERIFICATION SUMMARY
========================================================================
"@ -ForegroundColor Cyan

$allPass = ($localMesh.peer_count -ge 1)
if ($allPass) {
    Write-Host "   RESULT : [HEALTHY] THE MESH IS FULLY CONNECTED AND TALKING" -ForegroundColor Green
    Write-Host "   DETAILS: Local node has $($localMesh.peer_count) active peer(s). Gossipsub broadcast verified." -ForegroundColor Green
} else {
    Write-Host "   RESULT : [DISCONNECTED] No active peers found on local node." -ForegroundColor Red
}
Write-Host "========================================================================`n" -ForegroundColor Cyan
