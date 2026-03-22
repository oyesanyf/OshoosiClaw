# Windows Firewall Setup for OpenỌ̀ṣọ́ọ̀sì Mesh Defense
# Run as Administrator

$MeshPort = 4001
$DashboardPort = 8080

Write-Host "Configuring Windows Firewall for Mesh (Port $MeshPort) and Dashboard (Port $DashboardPort)..." -ForegroundColor Cyan

# 1. Mesh Port (P2P Gossip)
if (Get-NetFirewallRule -DisplayName "OpenOdidere Mesh (TCP)" -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -DisplayName "OpenOdidere Mesh (TCP)"
}
New-NetFirewallRule -DisplayName "OpenOdidere Mesh (TCP)" -Direction Inbound -LocalPort $MeshPort -Protocol TCP -Action Allow

if (Get-NetFirewallRule -DisplayName "OpenOdidere Mesh (UDP)" -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -DisplayName "OpenOdidere Mesh (UDP)"
}
New-NetFirewallRule -DisplayName "OpenOdidere Mesh (UDP)" -Direction Inbound -LocalPort $MeshPort -Protocol UDP -Action Allow

# 2. Dashboard Port (Web UI)
if (Get-NetFirewallRule -DisplayName "OpenOdidere Dashboard" -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -DisplayName "OpenOdidere Dashboard"
}
New-NetFirewallRule -DisplayName "OpenOdidere Dashboard" -Direction Inbound -LocalPort $DashboardPort -Protocol TCP -Action Allow

Write-Host "✅ Firewall rules added successfully." -ForegroundColor Green
