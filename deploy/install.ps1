# OpenỌ̀ṣọ́ọ̀sì Target-Side Installation Helper
# 1. Install/Update Sysmon
if (Test-Path "Sysmon64.exe") {
    echo "Installing Sysmon with security configuration..."
    .\Sysmon64.exe -i sysmonconfig-export.xml -accepteula
}
# 2. Grant permissions & Configure Firewall
echo "Ensuring administrative permissions and configuring firewall..."
.\osoosi.exe grant-access
netsh advfirewall firewall add rule name="Oshoosi Mesh TCP" dir=in action=allow protocol=TCP localport=4001
netsh advfirewall firewall add rule name="Oshoosi Mesh UDP" dir=in action=allow protocol=UDP localport=4001
netsh advfirewall firewall add rule name="Oshoosi mDNS UDP" dir=in action=allow protocol=UDP localport=5353
echo "Deployment complete. Start the agent with: .\osoosi.exe start"
